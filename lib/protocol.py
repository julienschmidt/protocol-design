"""
Base for scsync protocol implementations.
"""

import asyncio
import errno
import struct
import hashlib
import logging
import os
import io
import random

from typing import Any, Dict, Tuple
from enum import Enum, unique
from shutil import move
from tempfile import mkstemp

import aiofiles
import pyrsync2

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


from lib import files
from lib import sha256
from lib.buffer import ChunkRecvBuffer, ChunkSendBuffer

Address = Tuple[str, int]


@unique
class EncryptionMode(bytes, Enum):
    """
    Defined Encryption Modes
    """
    ChaCha20_Poly1305 = b'\x00'
    AES_128_GCM = b'\x01'
    AES_192_GCM = b'\x02'
    AES_256_GCM = b'\x03'


@unique
class PacketType(bytes, Enum):
    """
    scsync protocol packet types.
    """
    # unencrypted
    Client_Hello = b'\xF0'
    Challenge = b'\xF1'
    Challenge_Response = b'\xF2'
    Handshake_Error = b'\xFE'
    Ack_Handshake_Error = b'\xFF'

    # encrypted
    Error = b'\x00'
    Ack_Error = b'\x01'
    Client_Update_Request = b'\x10'
    Current_Server_State = b'\x11'
    Client_File_Request = b'\x12'
    File_Metadata = b'\x20'
    Ack_Metadata = b'\x21'
    File_Upload = b'\x22'
    Ack_Upload = b'\x23'
    File_Delete = b'\x24'
    Ack_Delete = b'\x25'
    File_Rename = b'\x26'
    Ack_Rename = b'\x27'
    File_Update_Request = b'\x28'
    File_Update_Response = b'\x29'
    File_Update = b'\x30'
    Ack_Update = b'\x31'


@unique
class ErrorType(bytes, Enum):
    """
    scsync protocol error types.
    """
    File_Hash_Error = b'\x00'
    Out_Of_Memory = b'\x01'
    Conflict = b'\x02'
    Upload_Failed = b'\x03'
    File_Not_Present = b'\x04'


class BaseScsyncProtocol(asyncio.DatagramProtocol):
    """
    Abstract base for scsync protocol implementations.
    Provides packing and unpacking of packets.
    """
    # pylint: disable=too-many-public-methods,no-self-use,unused-argument

    def __init__(self, loop, path, packets_per_second):
        self.loop = loop
        self.path = path
        self.packets_per_second = packets_per_second

        self.transport = None
        self.resend_delay = 1.0  # Fixed value because no congestion control
        self.chunk_size = 1024  # Should be adjusted to MTU later
        self.max_send_ahead = 4
        self.max_buf_ahead = 4

        # stores the fileinfo for the local files
        self.fileinfo = dict()

        # list dir
        local_files = files.list(path)
        for file in local_files:
            filename = file.encode('utf8')
            self.fileinfo[filename] = self.get_fileinfo(file)

        # epoch of last update
        self.epoch = 0

        self.sessions = dict()

        # Handle error callbacks and use to resend if no ack was received
        self.pending_error_callbacks = dict()

        # maps upload IDs to in-progress file uploads
        self.uploads = dict()

        # maps filenames to assigned upload IDs, used to check for conflicts and
        # to resume uploads
        self.active_uploads = dict()

        # Dictionaries for checking if ack/responses are pending
        self.pending_upload_acks = dict()
        self.pending_metadata_callbacks = dict()
        self.pending_delete_callbacks = dict()
        self.pending_rename_callbacks = dict()

        # Handle misleading delete callbacks because of move operation
        self.expected_delete_calls = list()

    def get_encryptor(self, enc_mode, session_key):
        if enc_mode == EncryptionMode.ChaCha20_Poly1305:
            return ChaCha20Poly1305(session_key)
        elif enc_mode == EncryptionMode.AES_256_GCM:
            return AESGCM(session_key)
        elif enc_mode == EncryptionMode.AES_192_GCM:
            return AESGCM(session_key[:24])
        elif enc_mode == EncryptionMode.AES_128_GCM:
            return AESGCM(session_key[:16])
        return None

    # File Handling

    def get_fileinfo(self, file) -> Dict[str, Any]:
        """
        Get meta information about the given file.
        """
        filepath = self.path + file
        statinfo = os.stat(filepath)
        filehash = sha256.hash_file(filepath)
        size = statinfo.st_size
        permissions = (statinfo.st_mode & 0o777)
        modified_at = statinfo.st_mtime

        if logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.debug("Got file info of file %s. " +
                          "[filehash: %s, size: %u, permissions: %o, modified_at: %u]",
                          file, sha256.hex(filehash), size, permissions, modified_at)
        return {
            'filehash': filehash,
            'size': size,
            'permissions': permissions,
            'modified_at': modified_at,
        }

    def set_metadata(self, filepath, permissions, modified_at):
        """
        Set file metadata for the given file.
        """
        os.chmod(filepath, permissions)
        os.utime(filepath, times=(modified_at, modified_at))

    def remove_expected_delete_calls(self, filename):
        if filename in self.expected_delete_calls:
            self.expected_delete_calls.remove(filename)

    # Packet Management

    def connection_made(self, transport) -> None:
        self.transport = transport

    def error_received(self, exc) -> None:
        logging.info('error received: %s', exc)

    def datagram_received(self, data, addr) -> None:
        logging.debug('received %d bytes from %s', len(data), addr)

        # Packet should at least contain the packet hash (32 Bytes) and the
        # packet type (1 Byte). All unencrypted packets are larger than that.
        if len(data) < 32 + 1:
            self.handle_invalid_packet(data, addr)
            return

        ptype = data[0:1]

        # determine by the packet type whether the packet should be encrypted
        encrypted = (ptype[0] < 0xE0)
        if encrypted:
            session_id = int.from_bytes(data[1:9], byteorder='big')
            nonce = data[9:21]

            session = self.sessions.get(session_id, None)
            if not session:
                logging.warning(
                    "no valid session for packet with session_id %u from %s", session_id, addr)
                self.handle_invalid_packet(data, addr)
                return

            try:
                data = session['encryptor'].decrypt(nonce, data[21:], None)
            except InvalidTag:
                logging.warning("invalid tag for packet from %s", addr)
                self.handle_invalid_packet(data, addr)
                return

            self.handle_valid_packet(ptype, session_id, data, addr)
        else:
            # check packet hash
            hash_i = len(data) - 32
            packethash = sha256.hash(data[:hash_i])
            if data[hash_i:] != packethash:
                logging.warning("hash invalid for packet from %s", addr)
                self.handle_invalid_packet(data, addr)
                return
            self.handle_unencrypted_packet(ptype, data[1:hash_i], addr)

    def sendto(self, data: bytes, session_id=None, addr=None) -> int:
        """
        Calculate and prepend a packet hash for the given data and send it as an
        UDP datagram.
        """

        nonce = None

        # determine by the packet type whether the packet should be encrypted
        encrypted = data[0] < 0xE0
        if encrypted:
            session = self.sessions.get(session_id, None)
            if not session:
                return 0

            nonce = session['nonce']
            session['nonce'] += 2
            nonce_b = nonce.to_bytes(12, byteorder='big')
            data = b''.join([
                data[0:1],
                session_id.to_bytes(8, byteorder='big'),
                nonce_b,
                session['encryptor'].encrypt(nonce_b, bytes(data[1:]), None)
            ])
        else:
            # add packet hash
            packethash = sha256.hash(data)
            data += packethash

        self.transport.sendto(data, addr)
        logging.debug('sent %d bytes (encrypted=%r, nonce=%s)', len(data), encrypted, nonce)

        return len(data)

    def handle_invalid_packet(self, data: bytes, addr: Address) -> None:
        """
        Handle invalid packets, such as with unknown packet types or invalid
        packet hashes.
        Should by overwritten by the child class.
        """
        logging.warning('received and dropped invalid packet from %s', addr)

    # Unencrypted Packets

    def handle_unencrypted_packet(self, ptype, data: bytes, addr: Address) -> None:
        """
        Handle valid but unencrypted packets by delegating them to the packet handling methods.
        """
        handle_methods = {
            PacketType.Client_Hello: self.handle_client_hello,
            PacketType.Challenge: self.handle_challenge,
            PacketType.Challenge_Response: self.handle_challenge_response,
            PacketType.Handshake_Error: self.handle_handshake_error,
            PacketType.Ack_Handshake_Error: self.handle_ack_handshake_error,
        }
        func = handle_methods.get(ptype, self.handle_invalid_packet)
        func(data, addr)

    def handle_client_hello(self, data: bytes, addr: Address) -> None:
        """
        Handle Client_Hello packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Client_Hello from %s', addr)
        return

    def handle_challenge(self, data: bytes, addr: Address) -> None:
        """
        Handle Challenge packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Challenge from %s', addr)
        return

    def handle_challenge_response(self, data: bytes, addr: Address) -> None:
        """
        Handle Challenge_Response packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Challenge_Response from %s', addr)
        return

    def handle_handshake_error(self, data: bytes, addr: Address) -> None:
        """
        Handle Handshake_Error packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Handshake_Error from %s', addr)
        return

    def handle_ack_handshake_error(self, data: bytes, addr: Address) -> None:
        """
        Handle Ack_Handshake_Error packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Ack_Handshake_Error from %s', addr)
        return

    # Encrypted Packets

    def handle_valid_packet(self, ptype, session_id: int, data: bytes, addr: Address) -> None:
        """
        Handle valid packets by delegating them to the packet handling methods.
        """
        handle_methods = {
            PacketType.Error: self.handle_error,
            PacketType.Ack_Error: self.handle_ack_error,
            PacketType.Client_Update_Request: self.handle_client_update_request,
            PacketType.Current_Server_State: self.handle_current_server_state,
            PacketType.Client_File_Request: self.handle_client_file_request,
            PacketType.File_Metadata: self.handle_file_metadata,
            PacketType.Ack_Metadata: self.handle_ack_metadata,
            PacketType.File_Upload: self.handle_file_upload,
            PacketType.Ack_Upload: self.handle_ack_upload,
            PacketType.File_Delete: self.handle_file_delete,
            PacketType.Ack_Delete: self.handle_ack_delete,
            PacketType.File_Rename: self.handle_file_rename,
            PacketType.Ack_Rename: self.handle_ack_rename,
            PacketType.File_Update_Request: self.handle_file_update_request,
            PacketType.File_Update_Response: self.handle_file_update_response,
            PacketType.File_Update: self.handle_file_update,
            PacketType.Ack_Update: self.handle_ack_update
        }
        func = handle_methods.get(
            ptype, self._handle_invalid_packet_wrap)
        func(session_id, data, addr)

    def _handle_invalid_packet_wrap(self, session_id: int, data: bytes, addr: Address) -> None:
        self.handle_invalid_packet(data, addr)

    def handle_error(self, session_id: int, data: bytes, addr: Address) -> None:
        """
        Handle Error packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Error from %s', addr)
        return

    def handle_ack_error(self, session_id: int, data: bytes, addr: Address) -> None:
        """
        Handle Ack_Error packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Ack_Error from %s', addr)
        return

    def handle_client_update_request(self, session_id: int, data: bytes, addr: Address) -> None:
        """
        Handle Client_Update_Request packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Client_Update_Request from %s', addr)
        return

    def handle_current_server_state(self, session_id: int, data: bytes, addr: Address) -> None:
        """
        Handle Current_Server_State packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Current_Server_State from %s', addr)
        return

    def handle_client_file_request(self, session_id: int, data: bytes, addr: Address) -> None:
        """
        Handle Client_File_Request packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Client_File_Request from %s', addr)
        return

    def handle_file_metadata(self, session_id: int, data: bytes, addr: Address) -> None:
        """
        Handle File_Metadata packets.
        Can be overwritten by the child class to handle this packet type.
        """

        valid, filehash, filename, size, permissions, modified_at = self.unpack_file_metadata(
            data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        if filename in self.fileinfo and filehash == self.fileinfo[filename]["filehash"]:
            # just adjust metadata, no reupload necessary
            upload_id = 0
            start_at = size
            filepath = self.path + filename.decode('utf8')
            self.set_metadata(filepath, permissions, modified_at)

        else:
            upload_id, start_at, error = self.init_upload(
                session_id, filehash, filename, size, permissions, modified_at)
            if error:
                self.communicate_error(
                    session_id, filename, filehash, error, addr=addr)
                return

        self.send_ack_metadata(session_id, filehash,
                               filename, upload_id, start_at, addr)

    def handle_ack_metadata(self, session_id: int, data: bytes, addr: Address) -> None:
        """
        Handle Ack_Metadata packets.
        Can by overwritten by the child class to handle this packet type.
        """

        valid, filehash, filename, upload_id, resume_at_byte = self.unpack_ack_metadata(
            data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        # cancel resend
        # if not self.cancel_resend(self.pending_metadata_callbacks, filename):
        #     print("EROOR: Cancel Resend")
        #     return

        fileinfo = self.fileinfo[filename]
        if fileinfo['size'] <= resume_at_byte:
            logging.debug("No further upload necessary")
            return
        if fileinfo['filehash'] != filehash:
            logging.error(
                "File changed in the meantime, filehash not the same!")
            return

        upload_task = self.loop.create_task(self.do_upload(
            session_id, filename, fileinfo, upload_id, resume_at_byte, addr))
        self.active_uploads[filename] = (upload_id, upload_task)

    def handle_file_upload(self, session_id: int, data: bytes, addr: Address) -> None:
        """
        Handle File_Uplaod packets.
        Can by overwritten by the child class to handle this packet type.
        """

        valid, upload_id, start_byte, payload = self.unpack_file_upload(
            data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        upload = self.uploads.get(upload_id, None)
        if upload is None:
            return
        chunk_queue = upload['chunk_queue']
        chunk_queue.put_nowait((start_byte, payload, addr))

    def handle_file_update(self, session_id: int, data: bytes, addr: Address) -> None:
        """
        Handle File_Update packets.
        Can by overwritten by the child class to handle this packet type.
        """

        valid, update_id, start_byte, payload = self.unpack_file_update(
            data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        upload = self.uploads.get(update_id, None)
        if upload is None:
            return
        chunk_queue = upload['chunk_queue']
        chunk_queue.put_nowait((start_byte, payload, addr))

    def handle_ack_upload(self, session_id: int, data: bytes, addr: Address) -> None:
        """
        Handle Ack_Upload packets.
        Can by overwritten by the child class to handle this packet type.
        """

        valid, upload_id, acked_bytes = self.unpack_ack_upload(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        ack = self.pending_upload_acks.get(upload_id, None)
        if ack is None:
            return

        if acked_bytes > ack[1]:
            ack[1] = acked_bytes
            ack[0].set()  # notify about new ACK

    def handle_ack_update(self, session_id: int, data: bytes, addr: Address) -> None:
        """
        Handle Ack_Update packets.
        Can by overwritten by the child class to handle this packet type.
        """

        valid, update_id, acked_bytes = self.unpack_ack_update(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        ack = self.pending_upload_acks.get(update_id, None)
        if ack is None:
            return

        if acked_bytes > ack[1]:
            ack[1] = acked_bytes
            ack[0].set()  # notify about new ACK

    def handle_file_delete(self, session_id: int, data: bytes, addr: Address) -> None:
        """
        Handle File_Delete packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received File_Delete from %s', addr)
        return

    def handle_ack_delete(self, session_id: int, data: bytes, addr: Address) -> None:
        """
        Handle Ack_Delete packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Ack_Delete from %s', addr)
        return

    def handle_file_rename(self, session_id: int, data: bytes, addr: Address) -> None:
        """
        Handle File_Rename packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received File_Rename from %s', addr)
        return

    def handle_ack_rename(self, session_id: int, data: bytes, addr: Address) -> None:
        """
        Handle Ack_Rename packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Ack_Rename from %s', addr)
        return

    def handle_file_update_request(self, session_id: int, data: bytes, addr: Address) -> None:
        """
        Handle File_Update_Request packets.
        Can be overwritten by the child class to handle this packet type.
        """
        valid, filehash, filename, filesize, permissions, modified_at = self.unpack_file_update_request(
            data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return
        # create new update entry and determine update_id
        upload_id, start_at, error = self.init_update(
            session_id, filehash, filename, filesize, permissions, modified_at)
        if error:
            self.communicate_error(session_id, filename,
                                   filehash, error, addr=addr)
            return

        # create checksums
        file = open(self.path + filename.decode("utf-8"), "rb")
        hashes = list(pyrsync2.blockchecksums(file, 16384))
        file.close()

        print("Update request received \"%s\"" % filename)
        self.send_file_update_response(
            session_id, filename, upload_id, start_at, hashes, addr)

    def handle_file_update_response(self, session_id: int, data: bytes, addr: Address) -> None:
        """
        Handle File_Update_Response packets.
        Can be overwritten by the child class to handle this packet type.
        """
        valid, filename, update_id, start_byte, checksums = self.unpack_file_update_response(
            data)

        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        file = open(self.path + filename.decode("utf-8"), "rb")
        delta = list(pyrsync2.rsyncdelta(file, checksums, 16384))
        file.close()

        # covert deta to bytearray encoded: len(4byte)|data(Xbyte), int fields
        # added as len=0
        data = bytes()
        for i in range(0, len(delta)):
            if isinstance(delta[i], int):
                # ints are just appended by length
                data += (0).to_bytes(4, byteorder='big')
            else:
                # data contained -> append
                data += (len(delta[i])).to_bytes(4, byteorder='big')
                data += delta[i]

        # start send delta to serverd
        self.upload_file_update(session_id, filename,
                                update_id, start_byte, data, addr)

        print("Update response received \"%s\"" % filename)

    def upload_file_update(self, session_id: int, filename, update_id, resume_at_byte, data, addr) -> None:
        print("Upload update of \"%s\"" % filename)

        # cancel any active upload for the same file
        active_update = self.active_uploads.get(filename, None)
        if not active_update is None:
            active_update[1].cancel()

        # upload
        update_task = self.loop.create_task(self.do_update(
            session_id, filename, update_id, resume_at_byte, data, addr))
        self.active_uploads[filename] = (update_id, update_task)

    def send_client_hello(self, request_id, username, client_seed, addr=None):
        """
        Pack and send a Client_Hello packet.
        """
        if not username or len(client_seed) != 256:
            return None
        data = b''.join([
            PacketType.Client_Hello,
            b'\x01',
            request_id.to_bytes(4, byteorder='big'),
            client_seed,
            (len(username)).to_bytes(1, byteorder='big'),
            username.encode('utf-8')
        ])
        return self.sendto(data, None, addr)

    def send_challenge(self, request_id, salt, server_seed, token, addr=None):
        """
        Pack and send a Challenge packet.
        """
        if not token or len(server_seed) != 256:
            return None
        data = b''.join([
            PacketType.Challenge,
            request_id.to_bytes(4, byteorder='big'),
            salt,
            server_seed,
            (len(token)).to_bytes(1, byteorder='big'),
            token
        ])
        return self.sendto(data, None, addr)

    def send_challenge_response(self, request_id, proof, client_seed, username,
                                token, enc_mode=EncryptionMode.AES_256_GCM,
                                addr=None):
        """
        Pack and send a Challenge_Response packet.
        """
        if not username or len(proof) != 32 or len(client_seed) != 256:
            return None
        data = b''.join([
            PacketType.Challenge_Response,
            request_id.to_bytes(4, byteorder='big'),
            proof,
            client_seed,
            enc_mode,
            (len(username)).to_bytes(1, byteorder='big'),
            username,
            (len(token)).to_bytes(1, byteorder='big'),
            token
        ])
        return self.sendto(data, None, addr)

    def send_client_update_request(self, session_id, epoch, addr=None):
        """
        Pack and send a Client_Update_Request packet.
        """
        data = PacketType.Client_Update_Request + \
            epoch.to_bytes(8, byteorder='big')
        return self.sendto(data, session_id, addr)

    def send_handshake_error(self, session_id: int, filename: bytes, filehash: bytes, error_type, error_id: int, description=None, addr=None) -> int:
        """
        Pack and send an Error packet.
        """
        data = b''.join([
            PacketType.Error,
            filehash,
            (len(filename)).to_bytes(2, byteorder='big'),
            filename,
            error_type,
            error_id.to_bytes(4, byteorder='big'),
            ((len(description)).to_bytes(2, byteorder='big')
             if description else bytes()),
            (description if description else bytes())
        ])
        return self.sendto(data, session_id, addr)

    def send_ack_handshake_error(self, session_id: int, error_id, addr=None) -> int:
        """
        Pack and send an Ack_Error packet.
        """
        data = b''.join([
            PacketType.Ack_Error,
            error_id.to_bytes(4, byteorder='big')
        ])
        return self.sendto(data, session_id, addr)

    def communicate_error(self, session_id: int, filename, filehash, error_type,
                          description=None, error_id=None, addr=None):
        if error_id is None:
            while True:
                error_id = random.getrandbits(32)
                if error_id not in self.pending_error_callbacks:
                    break

        # schedule resend (canceled if ack'ed)
        callback_handle = self.loop.call_later(
            self.resend_delay, self.communicate_error,
            filename, filehash, error_type, description, error_id, addr)
        self.pending_error_callbacks[error_id] = callback_handle

        logging.info('%s [%s]: %s %s', filename, sha256.hex(filehash),
                     error_type, description)
        self.send_error(session_id, filename, filehash, error_type,
                        error_id, description, addr)

    def send_error(self, session_id: int, filename: bytes, filehash: bytes,
                   error_type, error_id: int,
                   description=None, addr=None) -> int:
        """
        Pack and send an Error packet.
        """
        data = b''.join([
            PacketType.Error,
            filehash,
            (len(filename)).to_bytes(2, byteorder='big'),
            filename,
            error_type,
            error_id.to_bytes(4, byteorder='big'),
            ((len(description)).to_bytes(2, byteorder='big')
             if description else bytes()),
            (description if description else bytes())
        ])
        return self.sendto(data, session_id, addr)

    def send_ack_error(self, session_id: int, error_id, addr=None) -> int:
        """
        Pack and send an Ack_Error packet.
        """
        data = b''.join([
            PacketType.Ack_Error,
            error_id.to_bytes(4, byteorder='big')
        ])
        return self.sendto(data, session_id, addr)

    def send_current_server_state(self, session_id: int, fileinfos, addr=None):
        """
        Pack and send a Current_Server_State packet.
        """
        data = bytearray(PacketType.Current_Server_State)
        for filename, filehash in fileinfos.items():
            data.extend(filehash)
            data.extend((len(filename)).to_bytes(2, byteorder='big'))
            data.extend(filename)
        return self.sendto(data, session_id, addr)

    def send_client_file_request(self, session_id: int, filename, filehash, addr=None):
        """
        Pack and send a Client_File_Request packet.
        """

        data = bytearray(PacketType.Client_File_Request)
        data.extend(filehash)
        data.extend((len(filename)).to_bytes(2, byteorder='big'))
        data.extend(filename)

        return self.sendto(data, session_id, addr)

    def send_file_metadata(self, session_id: int, filename, fileinfo, addr=None):
        """
        Pack and send a File_Metadata packet.
        """
        filehash = fileinfo['filehash']
        size = fileinfo['size']
        permissions = fileinfo['permissions']
        modified_at = fileinfo['modified_at']
        data = b''.join([
            PacketType.File_Metadata,
            filehash,
            (len(filename)).to_bytes(2, byteorder='big'),
            filename,
            size.to_bytes(8, byteorder='big'),
            permissions.to_bytes(2, byteorder='big'),
            int(modified_at).to_bytes(4, byteorder='big')
        ])
        return self.sendto(data, session_id, addr)

    def send_ack_metadata(self, session_id: int, filehash, filename, upload_id, resume_at_byte=0, addr=None):
        """
        Pack and send a Ack_Metadata packet.
        """
        data = b''.join([
            PacketType.Ack_Metadata,
            filehash,
            (len(filename)).to_bytes(2, byteorder='big'),
            filename,
            upload_id.to_bytes(4, byteorder='big'),
            (resume_at_byte.to_bytes(8, byteorder='big')
             if resume_at_byte > 0 else bytes())
        ])
        return self.sendto(data, session_id, addr)

    def send_file_upload(self, session_id: int, upload_id, start_byte, payload, addr=None):
        """
        Pack and send a File_Upload packet.
        """
        data = b''.join([
            PacketType.File_Upload,
            upload_id.to_bytes(4, byteorder='big'),
            start_byte.to_bytes(8, byteorder='big'),
            (len(payload)).to_bytes(2, byteorder='big'),
            payload
        ])
        return self.sendto(data, session_id, addr)

    def send_file_update(self, session_id: int, update_id, start_byte, payload, addr=None):
        """
        Pack and send a File_Update packet.
        """
        data = b''.join([
            PacketType.File_Update,
            update_id.to_bytes(4, byteorder='big'),
            start_byte.to_bytes(8, byteorder='big'),
            (len(payload)).to_bytes(2, byteorder='big'),
            payload
        ])
        return self.sendto(data, session_id, addr)

    def send_ack_upload(self, session_id: int, upload_id, acked_bytes, addr=None):
        """
        Pack and send a Ack_Upload packet.
        """
        data = b''.join([
            PacketType.Ack_Upload,
            upload_id.to_bytes(4, byteorder='big'),
            acked_bytes.to_bytes(8, byteorder='big')
        ])
        return self.sendto(data, session_id, addr)

    def send_ack_update(self, session_id: int, update_id, acked_bytes, addr=None):
        """
        Pack and send a Ack_Update packet.
        """
        data = b''.join([
            PacketType.Ack_Update,
            update_id.to_bytes(4, byteorder='big'),
            acked_bytes.to_bytes(8, byteorder='big')
        ])
        return self.sendto(data, session_id, addr)

    def send_file_delete(self, session_id: int, filehash, filename, addr=None):
        """
        Pack and send a File_Delete packet.
        """
        data = b''.join([
            PacketType.File_Delete,
            filehash,
            (len(filename)).to_bytes(2, byteorder='big'),
            filename
        ])
        return self.sendto(data, session_id, addr)

    def send_file_update_request(self, session_id: int, filename, fileinfo, addr=None):
        """
        Request hashes from server for a specific file:
        """
        filehash = fileinfo['filehash']
        size = fileinfo['size']
        permissions = fileinfo['permissions']
        modified_at = fileinfo['modified_at']

        data = b''.join([
            PacketType.File_Update_Request,
            filehash,
            (len(filename)).to_bytes(2, byteorder='big'),
            filename,
            size.to_bytes(8, byteorder='big'),
            permissions.to_bytes(2, byteorder='big'),
            struct.pack("d", modified_at)
            #modified_at.to_bytes(4, byteorder='big')
        ])
        return self.sendto(data, session_id, addr)

    def send_file_update_response(self, session_id: int, filename, update_id, start_byte, hashes, addr=None):
        """
        Pack and send hashes for a specific file:
        """
        hash_data = bytes()

        for checksum, hash_val in hashes:
            # checksum 8 byte
            hash_data += struct.pack('>q', checksum)
            # hash 16 byte
            hash_data += hash_val

        data = b''.join([
            PacketType.File_Update_Response,
            update_id.to_bytes(4, byteorder='big'),
            start_byte.to_bytes(8, byteorder='big'),
            (len(filename)).to_bytes(2, byteorder='big'),
            filename,
            hash_data
        ])

        return self.sendto(data, session_id, addr)

    def send_ack_delete(self, session_id: int, filehash, filename, addr=None):
        """
        Pack and send a Ack_Delete packet.
        """
        data = b''.join([
            PacketType.Ack_Delete,
            filehash,
            (len(filename)).to_bytes(2, byteorder='big'),
            filename
        ])
        return self.sendto(data, session_id, addr)

    def send_file_rename(self, session_id: int, filehash, old_filename, new_filename, addr=None):
        """
        Pack and send a File_Rename packet.
        """
        data = b''.join([
            PacketType.File_Rename,
            filehash,
            (len(old_filename)).to_bytes(2, byteorder='big'),
            old_filename,
            (len(new_filename)).to_bytes(2, byteorder='big'),
            new_filename
        ])
        return self.sendto(data, session_id, addr)

    def send_ack_rename(self, session_id: int, filehash: bytes, old_filename, new_filename, addr=None):
        """
        Pack and send a Ack_Rename packet.
        """
        data = b''.join([
            PacketType.Ack_Rename,
            filehash,
            (len(old_filename)).to_bytes(2, byteorder='big'),
            old_filename,
            (len(new_filename)).to_bytes(2, byteorder='big'),
            new_filename
        ])
        return self.sendto(data, session_id, addr)

    def unpack_filehash_and_name(self, data: bytes):
        """
        Unpack packet and extract a filehash (32 Bytes) and a file name of
        variable length (2 Bytes length determiner) + Bytes to store name.
        Returning a tuple containing:
        (Success (Bool),
        Remaining Data in File (Bytes),
        File Hash (Bytes),
        Filename (Bytes))
        """

        # Check if the data packet at least stores enough data to store the
        # hash (32 Bytes) and filename length (2 Bytes)
        if len(data) < 32 + 2:
            logging.error(
                "packet not long enough to contain a filehash and a filename")
            return (False, None, None)

        # Parse filehash and filename length
        filehash = data[:32]
        filename_len = int.from_bytes(data[32:34], byteorder='big')

        if len(data) < 32 + 2 + filename_len:
            logging.error("packet too short for given filename length")
            return (False, None, None, None)

        filename = bytes(data[34:34 + filename_len])
        data = data[34 + filename_len:]

        return (True, data, filehash, filename)

    def unpack_error(self, data: bytes):
        """
        Unpack the Error packet from the given bytes (data).
        """

        # Parse filehash and filename
        valid, data, filehash, filename = self.unpack_filehash_and_name(data)
        if not valid or len(data) < 5:
            return (False, None, None, None, None, None)

        error_type = ErrorType(data[0].to_bytes(1, byteorder='big'))
        error_id = int.from_bytes(data[1:5], byteorder='big')

        description = None
        if len(data) >= 7:
            description_len = int.from_bytes(data[5:7], byteorder='big')
            if 7 + description_len != len(data):
                return (False, None, None, None, None, None)
            description = data[7:]

        return (True, filehash, filename, error_type, error_id, description)

    def unpack_ack_error(self, data: bytes):
        """
        Unpack the Ack_Error packet from the given bytes (data).
        """

        if len(data) != 4:
            return (False, None)
        error_id = int.from_bytes(data, byteorder='big')
        return (True, error_id)

    def unpack_client_hello(self, data: bytes):
        """
        Unpack the Client_Hello packet from the given bytes (data).
        """

        if len(data) < 1 + 4 + 256 + 1 + 1:
            logging.error("Client_Hello didn't have a valid length to parse")
            return (False, None, None, None)

        if data[0] != 0x01:
            logging.error("Unsupported protocol version")
            return (False, None, None, None)

        request_id = int.from_bytes(data[1:5], byteorder='big')
        client_seed = data[5:261]

        username_len = int(data[261])
        if len(data) != 262 + username_len:
            logging.error("Client_Hello packet did not have valid length")
            return (False, None, None, None)
        username = data[262:262 + username_len]

        logging.info(
            "successfully parsed Client_Hello for '%s' with RequestID %u", username, request_id)
        return (True, request_id, username, client_seed)

    def unpack_challenge(self, data: bytes):
        """
        Unpack the Challenge packet from the given bytes (data).
        """

        if len(data) < 4 + 4 + 256 + 1 + 1:
            logging.error("Challenge didn't have a valid length to parse")
            return (False, None, None, None, None)

        request_id = int.from_bytes(data[0:4], byteorder='big')
        salt = data[4:8]
        server_seed = data[8:264]

        token_len = int(data[264])
        if len(data) != 265 + token_len:
            logging.error("Challenge packet did not have valid length")
            return (False, None, None, None, None)
        token = data[265:265 + token_len]

        logging.info(
            "successfully parsed Challenge for RequestID %u", request_id)
        return (True, request_id, salt, server_seed, token)

    def unpack_challenge_response(self, data: bytes):
        """
        Unpack the Challenge_Response packet from the given bytes (data).
        """

        if len(data) < 4 + 32 + 256 + 1 + 1 + 1 + 1 + 1:
            logging.error(
                "Challenge_Response didn't have a valid length to parse")
            return (False, None, None, None, None, None, None)

        request_id = int.from_bytes(data[0:4], byteorder='big')
        proof = data[4:36]
        client_seed = data[36:292]
        enc_mode = EncryptionMode(data[292].to_bytes(1, byteorder='big'))

        username_len = int(data[293])
        if len(data) < 294 + username_len + 1 + 1:
            logging.error(
                "Challenge_Response packet did not have valid length1")
            return (False, None, None, None, None, None, None)
        username = data[294:294 + username_len]
        data = data[294 + username_len:]

        token_len = int(data[0])
        if len(data) != 1 + token_len:
            logging.error(
                "Challenge_Response packet did not have valid length2")
            return (False, None, None, None, None, None, None)
        token = data[1:1 + token_len]

        logging.info(
            "successfully parsed Challenge_Response for RequestID %u", request_id)
        return (True, request_id, proof, client_seed, enc_mode, username, token)

    def unpack_client_update_request(self, data: bytes):
        """
        Unpack the Client_Update_Request packet from the given bytes (data).
        """

        if len(data) != 8:
            logging.error(
                "Client_Update_Request didn't have a valid length to parse")
            return (False, None)

        epoch = int.from_bytes(data, byteorder='big')
        return (True, epoch)

    def unpack_current_server_state(self, data: bytes):
        """
        Unpack the Current_Server_State packet from the given bytes (data).
        """

        remote_files = {}
        while len(data) > 2 + 32:  # Min 2 Bytes for file filename_len and 32 Bytes for Hash
            valid, data, filehash, filename = self.unpack_filehash_and_name(
                data)
            if not valid:
                return (False, None)
            remote_files[filename] = filehash

        if data:
            logging.error("Current_Server_State did not have valid length, "
                          "there is data left after parsing all files")
            return (False, {})

        if logging.getLogger().isEnabledFor(logging.INFO):
            logging.info("successfully parsed Current_Server_State:")
            for filename, filehash in remote_files.items():
                logging.info("%s: %s", filename, sha256.hex(filehash))

        return (True, remote_files)

    def unpack_client_file_request(self, data: bytes):
        """
        Unpack the Client_File_Request packet from the given bytes (data).
        """

        # Parse filehash and filename
        valid, data, filehash, filename = self.unpack_filehash_and_name(data)
        if not valid:
            return (False, None, None)

        return (True, filehash, filename)

    def unpack_file_metadata(self, data: bytes):
        """
        Unpack the File_Metadata packet from the given bytes (data).
        """

        # Parse filehash and filename
        valid, data, filehash, filename = self.unpack_filehash_and_name(data)
        if not valid:
            return (False, None, None, None, None, None)

        # Check if the data packet stores enough data to store the size (8 Bytes),
        # permissions (2 Bytes), and modified_at date (4 Bytes)
        if len(data) != 8 + 2 + 4:
            logging.error("File_Metadata packet did not have valid length")
            return (False, None, None, None, None, None)

        # Parse filesize, permissions and modified_at
        filesize = int.from_bytes(data[:8], byteorder='big')
        permissions = int.from_bytes(data[8:10], byteorder='big')
        modified_at = int.from_bytes(data[10:14], byteorder='big')

        if logging.getLogger().isEnabledFor(logging.INFO):
            logging.info("successfully parsed File_Metadata of %s "
                         "(hash: %s). filesize: %u, permissions: %o, last modified at: %u",
                         filename, sha256.hex(filehash), filesize, permissions, modified_at)
        return (True, filehash, filename, filesize, permissions, modified_at)

    def unpack_ack_metadata(self, data: bytes):
        """
        Unpack the Ack_Metadata packet from the given bytes (data).
        """

        # Parse filehash and filename
        valid, data, filehash, filename = self.unpack_filehash_and_name(data)
        if not valid:
            return (False, None, None, None, None)

        # Check if the data packet stores enough data to store the upload_id (4
        # Bytes)
        if len(data) != 4 and len(data) != 4 + 8:
            logging.error("Ack_Metadata packet did not have valid length")
            return (False, None, None, None, None)

        # Parse upload_id and possibly resume_at_byte
        upload_id = int.from_bytes(data[:4], byteorder='big')
        resume_at_byte = int.from_bytes(
            data[4:12], byteorder='big') if len(data) == 4 + 8 else 0

        if logging.getLogger().isEnabledFor(logging.INFO):
            logging.info("successfully parsed Ack_Metadata for file %s (hash: %s). "
                         "upload ID: %u, resume at byte: %u",
                         filename, sha256.hex(filehash), upload_id, resume_at_byte)
        return (True, filehash, filename, upload_id, resume_at_byte)

    def unpack_file_upload(self, data: bytes):
        """
        Unpack the File_Upload packet from the given bytes (data).
        """

        # Check if the data packet stores enough data to at least store the upload_id (4 Bytes),
        # payload_start_byte (8 Bytes) and the payload_len (2 Bytes)
        if len(data) < 4 + 8 + 2:
            logging.error("File_Upload packet did not have valid length")
            return (False, None, None, None)

        upload_id = int.from_bytes(data[:4], byteorder='big')
        payload_start_byte = int.from_bytes(data[4:12], byteorder='big')
        payload_len = int.from_bytes(data[12:14], byteorder='big')
        data = data[4 + 8 + 2:]

        if len(data) != payload_len:
            logging.error("File_Upload packet did not have valid length")
            return (False, None, None, None)
        payload = data

        logging.info("successfully parsed File_Upload with upload ID: %u. "
                     "The payload starts at byte %u and has length %u",
                     upload_id, payload_start_byte, len(payload))
        return (True, upload_id, payload_start_byte, payload)

    def unpack_file_update(self, data: bytes):
        """
        Unpack the File_Upload packet from the given bytes (data).
        """

        # Check if the data packet stores enough data to at least store the update_id (4 Bytes),
        # payload_start_byte (8 Bytes) and the payload_len (2 Bytes)
        if len(data) < 4 + 8 + 2:
            logging.error("File_Update packet did not have valid length")
            return (False, None, None, None)

        update_id = int.from_bytes(data[:4], byteorder='big')
        payload_start_byte = int.from_bytes(data[4:12], byteorder='big')
        payload_len = int.from_bytes(data[12:14], byteorder='big')
        data = data[4 + 8 + 2:]

        if len(data) != payload_len:
            logging.error("File_Update packet did not have valid length")
            return (False, None, None, None)
        payload = data

        logging.info("successfully parsed File_Update with upload ID: %u. "
                     "The payload starts at byte %u and has length %u",
                     update_id, payload_start_byte, len(payload))
        return (True, update_id, payload_start_byte, payload)

    def unpack_ack_upload(self, data: bytes):
        """
        Unpack the Ack_Upload packet from the given bytes (data).
        """

        # Check if the data packet stores enough data to at least store the
        # upload_id (4 Bytes) and the acked_bytes (8 Bytes)
        if len(data) != 4 + 8:
            logging.error("Ack_Upload packet did not have valid length")
            return (False, None, None)

        upload_id = int.from_bytes(data[:4], byteorder='big')
        acked_bytes = int.from_bytes(data[4:12], byteorder='big')

        logging.info("successfully parsed Ack_Upload for upload ID: %u. "
                     "Acknowledged all bytes until %u",
                     upload_id, acked_bytes)
        return (True, upload_id, acked_bytes)

    def unpack_ack_update(self, data: bytes):
        """
        Unpack the Ack_Update packet from the given bytes (data).
        """

        # Check if the data packet stores enough data to at least store the
        # update_id (4 Bytes) and the acked_bytes (8 Bytes)
        if len(data) != 4 + 8:
            logging.error("Ack_Update packet did not have valid length")
            return (False, None, None)

        update_id = int.from_bytes(data[:4], byteorder='big')
        acked_bytes = int.from_bytes(data[4:12], byteorder='big')

        logging.info("successfully parsed Ack_Update for update ID: %u. "
                     "Acknowledged all bytes until %u",
                     update_id, acked_bytes)
        return (True, update_id, acked_bytes)

    def unpack_file_delete(self, data: bytes):
        """
        Unpack the File_Delete packet from the given bytes (data).
        """

        # Parse filehash and filename
        valid, data, filehash, filename = self.unpack_filehash_and_name(data)
        if not valid or data:
            logging.error("File_Delete packet did not have valid length")
            return (False, None, None)

        if logging.getLogger().isEnabledFor(logging.INFO):
            logging.info("successfully parsed File_Delete for file %s (hash: %s).",
                         filename, sha256.hex(filehash))
        return (True, filehash, filename)

    def unpack_ack_delete(self, data: bytes):
        """
        Unpack the Ack_Delete packet from the given bytes (data).
        """

        # Parse filehash and filename
        valid, data, filehash, filename = self.unpack_filehash_and_name(data)
        if not valid or data:
            logging.error("Ack_Delete packet did not have valid length")
            return (False, None, None)

        if logging.getLogger().isEnabledFor(logging.INFO):
            logging.info("successfully parsed Ack_Delete for file %s (hash: %s)",
                         filename, sha256.hex(filehash))
        return (True, filehash, filename)

    def unpack_file_rename(self, data: bytes):
        """
        Unpack the File_Rename packet from the given bytes (data).
        """

        # Parse filehash and filename
        valid, data, filehash, old_filename = self.unpack_filehash_and_name(
            data)

        if not valid or len(data) <= 2:
            logging.error("File_Rename packet did not have valid length")
            return (False, None, None, None)

        new_filename_len = int.from_bytes(data[:2], byteorder='big')
        if len(data) != 2 + new_filename_len:
            logging.error("File_Rename packet did not have valid length")
            return (False, None, None, None)

        new_filename = data[2:2 + new_filename_len]

        if logging.getLogger().isEnabledFor(logging.INFO):
            logging.info("successfully parsed File_Rename packet for file %s (hash: %s)."
                         "Should be renamed to %s",
                         old_filename, sha256.hex(filehash), new_filename)
        return (True, filehash, old_filename, new_filename)

    def unpack_ack_rename(self, data: bytes):
        """
        Unpack the Ack_Rename packet from the given bytes (data).
        """

        # Parse filehash and filename
        valid, data, filehash, old_filename = self.unpack_filehash_and_name(
            data)

        if not valid or len(data) <= 2:
            logging.warning("Ack_Rename did not have valid length")
            return (False, None, None, None)

        new_filename_len = int.from_bytes(data[:2], byteorder='big')
        if len(data) != 2 + new_filename_len:
            logging.warning("Ack_Rename did not have valid length")
            return (False, None, None, None)

        new_filename = data[2:2 + new_filename_len]

        if logging.getLogger().isEnabledFor(logging.INFO):
            logging.info("successfully parsed Ack_Rename for file %s (hash: %s)."
                         "Should be renamed to %s",
                         old_filename, sha256.hex(filehash), new_filename)
        return (True, filehash, old_filename, new_filename)

    def unpack_file_update_request(self, data: bytes):
        # Parse filehash and filename
        valid, data, filehash, filename = self.unpack_filehash_and_name(data)
        if not valid:
            return (False, None, None, None, None, None)

        # Check if the data packet stores enough data to store the size (8 Bytes),
        # permissions (2 Bytes), and modified_at date (4 Bytes)
        if len(data) != 8 + 2 + 8:
            logging.error(
                "File_Update_Request packet did not have valid length")
            return (False, None, None, None, None, None)

        # Parse filesize, permissions and modified_at
        filesize = int.from_bytes(data[:8], byteorder='big')
        permissions = int.from_bytes(data[8:10], byteorder='big')
        modified_at = struct.unpack("d", data[10:18])[0]

        if logging.getLogger().isEnabledFor(logging.INFO):
            logging.info("successfully parsed File_Update_Request of %s "
                         "(hash: %s). filesize: %u, permissions: %o, last modified at: %u",
                         filename, sha256.hex(filehash), filesize, permissions, modified_at)
        return (True, filehash, filename, filesize, permissions, modified_at)

    def unpack_file_update_response(self, data: bytes):
        if len(data) < 12:
            logging.error(
                "packet not long enough to contain a update_id and resume_at_byte")
            return (False, None, None, None, None)
        # Parse update_id and possibly resume_at_byte
        update_id = int.from_bytes(data[:4], byteorder='big')
        resume_at_byte = int.from_bytes(data[4:12], byteorder='big')

        if len(data) < 12 + 2:
            logging.error(
                "packet not long enough to contain a filename")
            return (False, None, None, None, None)
        filename_len = int.from_bytes(data[12:14], byteorder='big')

        if len(data) < 12 + 2 + filename_len:
            logging.warning("File_Update_Request did not have valid length")
            return (False, None, None, None, None)
        filename = data[14:14 + filename_len]

        if len(data) < 12 + 2 + filename_len + 8 + 16:
            logging.warning(
                "File_Update_Response did not contain a valid checksum/hash pair.")
            return (False, None, None, None, None)

        checksums = []
        i = 12 + 2 + filename_len
        while i < len(data):
            checksums.append(
                (struct.unpack('>q', data[i:i + 8])[0], data[i + 8:i + 24]))
            i += 24

        return (True, filename, update_id, resume_at_byte, checksums)

    # File Upload Receiver Code

    def gen_upload_id(self):
        """
        Generates a unique upload ID.
        """
        while True:
            upload_id = random.getrandbits(32)
            if upload_id not in self.uploads:
                return upload_id

    def cancel_resend(self, register, key) -> bool:
        if key is None:
            callback_handle = register
            if callback_handle is None:
                return False
            callback_handle.cancel()
            register = None
            return True
        else:
            callback_handle = register.get(key, None)
            if callback_handle is None:
                return False
            callback_handle.cancel()
            del register[key]
            return True

    def init_upload(self, session_id, filehash, filename, size, permissions, modified_at):
        """
        Initialize a new file upload and return the assigned upload ID.
        """

        print("Receiving new file upload of file \"%s\" with size of %s bytes" % (
            filename, size))

        # check for existing upload to resume
        if filename in self.active_uploads:
            upload_id, _ = self.active_uploads[filename]
            upload = self.uploads[upload_id]

            if upload['filehash'] == filehash and upload['size'] == size:
                # resume upload
                upload['permissions'] = permissions
                upload['modified_at'] = modified_at
                start_at = upload['next_byte']
                logging.info("resume upload at byte %u", start_at)
                return (upload_id, start_at, None)

            elif upload['modified_at'] >= modified_at:
                # only accept newer files
                return (0, 0, ErrorType.Conflict)

        start_at = 0
        upload_id = self.gen_upload_id()
        upload = {
            'filehash': filehash,
            'filename': filename,
            'size': size,
            'permissions': permissions,
            'modified_at': modified_at,

            'tmpfile': mkstemp(),
            'next_byte': 0,

            # Queue to pass chunks to the receiver coroutine
            'chunk_queue': asyncio.Queue(loop=self.loop),
        }

        upload_task = self.loop.create_task(
            self.receive_upload(session_id, upload_id, upload))
        self.uploads[upload_id] = upload
        self.active_uploads[filename] = (upload_id, upload_task)

        return (upload_id, start_at, None)

    def init_update(self, session_id, filehash, filename, size, permissions, modified_at):
        """
        Initialize a new file upload and return the assigned upload ID.
        """

        print("Receiving new file update of file \"%s\" with size of %s bytes" % (
            filename, size))

        # check for existing upload to resume
        if filename in self.active_uploads:
            update_id, _ = self.active_uploads[filename]
            upload = self.uploads[update_id]

            if upload['filehash'] == filehash and upload['size'] == size:
                # resume upload
                upload['permissions'] = permissions
                upload['modified_at'] = modified_at
                start_at = upload['next_byte']
                logging.info("resume update at byte %u", start_at)
                return (update_id, start_at, None)

            elif upload['modified_at'] >= modified_at:
                # only accept newer files
                return (0, 0, ErrorType.Conflict)

        start_at = 0
        update_id = self.gen_upload_id()
        upload = {
            'filehash': filehash,
            'filename': filename,
            'size': size,
            'permissions': permissions,
            'modified_at': modified_at,

            'tmpfile': mkstemp(),
            'next_byte': 0,

            # Queue to pass chunks to the receiver coroutine
            'chunk_queue': asyncio.Queue(loop=self.loop),
        }

        upload_task = self.loop.create_task(
            self.receive_update(session_id, update_id, upload))
        self.uploads[update_id] = upload
        self.active_uploads[filename] = (update_id, upload_task)

        return (update_id, start_at, None)

    async def receive_upload(self, session_id, upload_id, upload):
        """
        This coroutine waits for incoming file chunks and writes them to the
        temporary file. When the whole file has been received, the filehash
        is verified before moving the file to the final destination and updating
        the cached fileinfo.
        """
        size = upload['size']
        tmpfile = upload['tmpfile'][1]
        m = hashlib.sha256()
        error = None
        if size > 0:
            try:
                async with aiofiles.open(tmpfile, mode='wb', loop=self.loop) as f:
                    chunk_queue = upload['chunk_queue']
                    buffered_chunks = ChunkRecvBuffer(self.max_buf_ahead)
                    pos = 0
                    while pos < size:
                        # TODO: add timeout
                        start_byte, payload, addr = await chunk_queue.get()
                        logging.debug("chunk %s, %s, %s", pos,
                                      start_byte, len(payload))
                        if start_byte != pos:
                            if start_byte > pos:
                                # ignore chunks with invalid start byte
                                if start_byte > size:
                                    continue

                                # buffer chunks which can not be immediately
                                # written
                                buffered_chunks.put(start_byte, payload)
                                continue

                            # skip old data
                            diff = pos - start_byte
                            if diff > len(payload):
                                continue
                            payload = payload[diff:]

                        pos += len(payload)

                        # get max available consecutive byte when including
                        # buffered chunks
                        available, matching_chunks = buffered_chunks.max_available(
                            pos)
                        upload['next_byte'] = available

                        # send ack with max available byte
                        self.send_ack_upload(
                            session_id, upload_id, available, addr)

                        # update hash and write to file
                        m.update(payload)
                        await f.write(payload)

                        # handle buffered chunks that can be written now
                        while matching_chunks > 0:
                            start_byte, payload = buffered_chunks.pop()

                            # skip old data
                            diff = pos - start_byte
                            if diff > len(payload):
                                continue
                            payload = payload[diff:]

                            pos += len(payload)
                            m.update(payload)
                            await f.write(payload)
                            matching_chunks -= 1
            except (asyncio.CancelledError, RuntimeError):
                return
            except IOError as e:
                description = os.strerror(e.errno)
                logging.error('IOError %u: %s', e.errno, description)
                if e.errno in [errno.ENOSPC, errno.ENOMEM, errno.EFBIG]:
                    error = (ErrorType.Out_Of_Memory, description)
                else:
                    error = (ErrorType.Upload_Failed, description)

        filehash = m.digest()
        filename = upload['filename']

        del self.uploads[upload_id]
        del self.active_uploads[filename]

        if filehash != upload['filehash'] and error is None:
            logging.error('filehash of file \"%s\" did not match!', filename)
            error = (ErrorType.File_Hash_Error, "filehash does not match")

        if error is not None:
            os.remove(tmpfile)
            self.communicate_error(filename, filehash, error[0],
                                   bytes(error[1]), None, addr)
            return

        # update cached fileinfo
        self.fileinfo[filename] = {
            'filehash': filehash,
            'size': size,
            'permissions': upload['permissions'],
            'modified_at': upload['modified_at'],
        }

        filepath = self.path + filename.decode('utf8')

        # A delete call might be triggered when moving the file
        self.expected_delete_calls.append(filename)
        move(tmpfile, filepath)
        self.loop.call_later(0.5, self.remove_expected_delete_calls, filename)

        self.set_metadata(
            filepath, upload['permissions'], upload['modified_at'])

        print("finished upload of file \"%s\"" % filename)

    async def receive_update(self, session_id, upload_id, upload):
        """
        This coroutine waits for incoming update chunks and stores them in a byte array.
        When the whole update delta information has been received, the filehash
        is verified before updating the file to the final destination and updating
        the cached fileinfo.
        """
        size = upload['size']
        tmpfile = upload['tmpfile'][1]
        error = None
        data = b''
        if size > 0:
            try:

                chunk_queue = upload['chunk_queue']
                buffered_chunks = ChunkRecvBuffer(self.max_buf_ahead)
                pos = 0
                while pos < size:

                    # TODO: add timeout
                    start_byte, payload, addr = await chunk_queue.get()
                    # if startbyte 0: update size
                    if start_byte == 0:
                        size = int.from_bytes(payload[0:8], byteorder='big')

                    logging.debug("chunk %s, %s, %s", pos,
                                  start_byte, len(payload))
                    if start_byte != pos:
                        if start_byte > pos:
                            # ignore chunks with invalid start byte
                            if start_byte > size:
                                continue

                            # buffer chunks which can not be immediately
                            # written
                            buffered_chunks.put(start_byte, payload)
                            continue

                        # skip old data
                        diff = pos - start_byte
                        if diff > len(payload):
                            continue
                        payload = payload[diff:]

                    pos += len(payload)

                    # get max available consecutive byte when including
                    # buffered chunks
                    available, matching_chunks = buffered_chunks.max_available(
                        pos)
                    upload['next_byte'] = available
                    # send ack with max available byte
                    self.send_ack_update(
                        session_id, upload_id, available, addr)
                    # add data
                    data += payload
                    # handle buffered chunks that can be written now
                    while matching_chunks > 0:
                        start_byte, payload = buffered_chunks.pop()

                        # skip old data
                        diff = pos - start_byte
                        if diff > len(payload):
                            continue
                        payload = payload[diff:]

                        pos += len(payload)
                        data += payload
                        matching_chunks -= 1
            except (asyncio.CancelledError, RuntimeError):
                return
            except IOError as e:
                description = os.strerror(e.errno)
                logging.error('IOError %u: %s', e.errno, description)
                if e.errno in [errno.ENOSPC, errno.ENOMEM, errno.EFBIG]:
                    error = (ErrorType.Out_Of_Memory, description)
                else:
                    error = (ErrorType.Upload_Failed, description)

        filename = upload['filename']

        del self.uploads[upload_id]
        del self.active_uploads[filename]

        if error is not None:
            os.remove(tmpfile)
            self.communicate_error(filename, upload['filehash'], error[
                                   0], bytes(error[1]), None, addr)
            return

        # Process received data
        # remove first 8 bytes: delta size
        data = data[8:]
        # remove 32 bytes: hash
        upload_hash = data[:32]
        data = data[32:]

        # check
        if sha256.hash(data) != upload_hash and error is None:
            logging.error('deltahash for file \"%s\" did not match!', filename)
            error = (ErrorType.File_Hash_Error, "deltahash does not match")

        # generate delta list structure
        i = 0
        index_cnt = 0
        delta_list = []
        last_filled = False
        while i < len(data):
            checksum_length = int.from_bytes(data[i:i + 4], byteorder='big')
            if checksum_length == 0:
                # special case when i == 0, index used is 0, otherwise a non
                # int has been before, therefore index++
                if i == 0:
                    delta_list.append(0)
                else:
                    index_cnt += 1
                    delta_list.append(index_cnt)
                i = i + 4
                last_filled = False
            else:
                if not last_filled and i != 0:
                    index_cnt += 1
                    last_filled = True
                else:
                    # only for the i == 0 case important
                    last_filled = True
                # contains data, add the data
                delta_list.append(data[i + 4:i + 4 + checksum_length])
                i = i + 4 + checksum_length

        # update
        file = open(self.path + filename.decode("utf-8"), "rb")
        file.seek(0)
        save_to = open(tmpfile, "wb")
        pyrsync2.patchstream(file, save_to, delta_list, 16384)
        file.close()
        save_to.close()

        # check updated file size/hash
        filehash = sha256.hash_file(tmpfile)
        statinfo = os.stat(tmpfile)
        size = statinfo.st_size

        if filehash != upload['filehash'] and error is None:
            logging.error(
                'updated filehash for file \"%s\" did not match!', filename)
            error = (ErrorType.File_Hash_Error, "updated hash does not match")

        if size != upload['size'] and error is None:
            logging.error(
                'updated size for file \"%s\" did not match!', filename)
            # TODO new error type for size missmatch (?)
            error = (ErrorType.File_Hash_Error, "updated size does not match")

        filepath = self.path + filename.decode('utf8')
        # A delete call might be triggered when moving the file
        self.expected_delete_calls.append(filename)
        move(tmpfile, filepath)
        self.loop.call_later(0.5, self.remove_expected_delete_calls, filename)

        self.set_metadata(
            filepath, upload['permissions'], upload['modified_at'])

        # update cached fileinfo
        self.fileinfo[filename] = {
            'filehash': filehash,
            'size': size,
            'permissions': upload['permissions'],
            'modified_at': upload['modified_at'],
        }

        print("finished update of file \"%s\"" % filename)

    # File Upload Sender Code
    def upload_file(self, session_id, filename, fileinfo=None, addr=None) -> None:
        """
        Upload the given file to server.
        """
        if fileinfo is None:
            fileinfo = self.get_fileinfo(filename.decode('utf8'))
            # prevent double uploads do to IO-notifications (e.g. create and
            # modify)
            existing_fileinfo = self.fileinfo.get(filename, None)
            if existing_fileinfo is not None and existing_fileinfo == fileinfo:
                return
        self.fileinfo[filename] = fileinfo
        print("Upload \"%s\"" % filename)

        # cancel any active upload for the same file
        active_upload = self.active_uploads.get(filename, None)
        if active_upload is not None:
            active_upload[1].cancel()

        # schedule resend (canceled if ack'ed)
        # callback_handle = self.loop.call_later(self.resend_delay, self.upload_file, filename, fileinfo, addr)
        # self.pending_metadata_callbacks[filename] = callback_handle

        # send file metadata
        self.send_file_metadata(session_id, filename, fileinfo)

    async def do_update(self, session_id: int, filename: bytes, update_id: int, resume_at_byte: int, data: bytes, addr) -> None:
        """
        This coroutine sends update delta data as
        File_Update packets. It then waits for acknowledgment and resends
        the packet if the sent chunk is not acknowledged.
        """
        filepath = self.path + filename.decode('utf8')
        size = len(data)
        deltahash = sha256.hash(data)

        # add size of the data (to update receiver thread) and hash
        data = b''.join([size.to_bytes(8, byteorder='big'),
                         deltahash,
                         data])
        try:
            with io.BytesIO(data) as f:
                buf_size = self.chunk_size

                pos = 0
                if 0 < resume_at_byte <= size:
                    f.seek(pos)
                    pos = resume_at_byte
                ack = [asyncio.Event(loop=self.loop), pos]
                self.pending_upload_acks[update_id] = ack
                acked_bytes = pos
                # buffer for sent but not yet acknowledged chunks
                chunk_buffer = ChunkSendBuffer()
                while acked_bytes < size:
                    # TODO: `ahead` should be global
                    while pos < size and chunk_buffer.length < self.max_send_ahead:
                        logging.debug('reading chunk from pos %u', pos)
                        # read chunk from file
                        buf = f.read(buf_size)
                        if not buf:
                            return

                        # send chunk
                        self.send_file_update(
                            session_id, update_id, pos, buf, addr)
                        expiry_time = self.loop.time() + self.resend_delay
                        chunk_buffer.put(expiry_time, pos, buf)
                        pos += len(buf)

                        # Congestion Control
                        await asyncio.sleep(1 / self.packets_per_second)

                        # check status
                        if ack[0].is_set(): # type: ignore
                            ack[0].clear() # type: ignore
                            acked_bytes = ack[1] # type: ignore
                            logging.debug('got acks until %u', acked_bytes)
                            current_time = self.loop.time()
                            expired_chunks = chunk_buffer.adjust(
                                current_time, acked_bytes)
                            if expired_chunks:
                                self.resend_chunks(
                                    session_id, expired_chunks, update_id, chunk_buffer, addr)

                    # wait blocking for ack
                    current_time = self.loop.time()
                    min_expiry_time = chunk_buffer.min_expiry_time()
                    if min_expiry_time is None:
                        continue
                    timeout = min_expiry_time - current_time
                    if timeout > 0:
                        try:
                            await asyncio.wait_for(ack[0].wait(), # type: ignore
                                                   timeout=timeout,
                                                   loop=self.loop)
                        except asyncio.TimeoutError:
                            pass
                    ack[0].clear() # type: ignore
                    acked_bytes = ack[1] # type: ignore
                    logging.debug('got acks until %u', acked_bytes)
                    expired_chunks = chunk_buffer.adjust(
                        current_time, acked_bytes)
                    if expired_chunks:
                        self.resend_chunks(
                            session_id, expired_chunks, update_id, chunk_buffer, addr)

        except RuntimeError:
            return
        except IOError as e:
            description = os.strerror(e.errno)
            logging.error('IOError %u: %s', e.errno, description)
            del self.active_uploads[filename]
            self.loop.call_soon(self.upload_file, session_id, filename,
                                self.get_fileinfo(filename.decode('utf8')), addr)
            return

        del self.active_uploads[filename]
        print("Update of file \"%s\" was finished" % filename)

    async def do_upload(self, session_id, filename, fileinfo, upload_id, resume_at_byte, addr) -> None:
        """
        This coroutine reads chunks from the given file and sends it as
        File_Upload packets. It then waits for acknowledgment and resends
        the packet if the sent chunk is not acknowledged.
        """
        filepath = self.path + filename.decode('utf8')
        size = fileinfo['size']
        try:
            async with aiofiles.open(filepath, mode='rb', loop=self.loop) as f:
                buf_size = self.chunk_size

                pos = 0
                if 0 < resume_at_byte <= size:
                    await f.seek(pos)
                    pos = resume_at_byte

                ack = [asyncio.Event(loop=self.loop), pos]
                self.pending_upload_acks[upload_id] = ack
                acked_bytes = pos

                # buffer for sent but not yet acknowledged chunks
                chunk_buffer = ChunkSendBuffer()
                while acked_bytes < size:
                    # TODO: `ahead` should be global
                    while pos < size and chunk_buffer.length < self.max_send_ahead:
                        logging.debug('reading chunk from pos %u', pos)
                        # read chunk from file
                        buf = await f.read(buf_size)
                        if not buf:
                            return

                        # send chunk
                        self.send_file_upload(
                            session_id, upload_id, pos, buf, addr=addr)

                        expiry_time = self.loop.time() + self.resend_delay
                        chunk_buffer.put(expiry_time, pos, buf)
                        pos += len(buf)

                        # Congestion Control
                        await asyncio.sleep(1 / self.packets_per_second)

                        # check status
                        if ack[0].is_set(): # type: ignore
                            ack[0].clear() # type: ignore
                            acked_bytes = ack[1] # type: ignore
                            logging.debug('got acks until %u', acked_bytes)
                            current_time = self.loop.time()
                            expired_chunks = chunk_buffer.adjust(
                                current_time, acked_bytes)
                            if expired_chunks:
                                self.resend_chunks(
                                    session_id, expired_chunks, upload_id, chunk_buffer, addr)

                    # wait blocking for ack
                    current_time = self.loop.time()
                    min_expiry_time = chunk_buffer.min_expiry_time()
                    if min_expiry_time is None:
                        continue
                    timeout = min_expiry_time - current_time
                    if timeout > 0:
                        try:
                            await asyncio.wait_for(ack[0].wait(), # type: ignore
                                                   timeout=timeout,
                                                   loop=self.loop)
                        except asyncio.TimeoutError:
                            pass
                    ack[0].clear() # type: ignore
                    acked_bytes = ack[1] # type: ignore
                    logging.debug('got acks until %u', acked_bytes)
                    expired_chunks = chunk_buffer.adjust(
                        current_time, acked_bytes)
                    if expired_chunks:
                        self.resend_chunks(
                            session_id, expired_chunks, upload_id, chunk_buffer, addr)

        except RuntimeError:
            return
        except IOError as e:
            description = os.strerror(e.errno)
            logging.error('IOError %u: %s', e.errno, description)
            del self.active_uploads[filename]
            self.loop.call_soon(self.upload_file, session_id,
                                filename, fileinfo, addr)
            return

        del self.active_uploads[filename]
        print("Upload of file \"%s\" was finished" % filename)

    def resend_chunks(self, session_id: int, expired_chunks, upload_id: int, chunk_buffer, addr):
        expiry_time = self.loop.time() + self.resend_delay
        for chunk in expired_chunks:
            logging.info("resending chunk starting at byte %u", chunk[1])
            self.send_file_upload(session_id, upload_id, chunk[
                                  1], chunk[2], addr=addr)
            chunk_buffer.put(expiry_time, chunk[1], chunk[2])
