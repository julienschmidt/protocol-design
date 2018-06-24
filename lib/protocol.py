"""
Base for scsync protocol implementations.
"""

import asyncio
import logging
import os
import struct

from typing import Dict, Any
from enum import Enum, unique
from typing import Tuple

from . import sha256


Address = Tuple[str, int]


@unique
class PacketType(bytes, Enum):
    """
    scsync protocol packet types.
    """
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
    File_Update_Request= b'\x28'
    File_Update_Response= b'\x29'
    File_Update= b'\x30'
    Ack_Update= b'\x31'


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

    def __init__(self, path):
        self.path = path

        self.transport = None
        self.resend_delay = 1.0  # Fixed value because no congestion control
        self.chunk_size = 1024  # Should be adjusted to MTU later
        self.max_send_ahead = 4

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

    def connection_made(self, transport) -> None:
        self.transport = transport

    def error_received(self, exc) -> None:
        logging.info('error received: %s', exc)

    def datagram_received(self, data, addr) -> None:
        logging.debug('received %d bytes from %s', len(data), addr)

        # Packet should at least contain the packet hash (32 Bytes) and the
        # packet type (1 Byte)
        if len(data) < 32 + 1:
            self.handle_invalid_packet(data, addr)
            return

        # check packet hash
        packethash = sha256.hash(data[32:])
        if data[:32] != packethash:
            logging.warning("hash invalid for packet from %s", addr)
            self.handle_invalid_packet(data, addr)
            return

        self.handle_valid_packet(data[32:32 + 1], data[32 + 1:], addr)

    def handle_valid_packet(self, ptype, data: bytes, addr: Address) -> None:
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
        func = handle_methods.get(ptype, self.handle_invalid_packet)
        func(data, addr)

    def handle_error(self, data: bytes, addr: Address) -> None:
        """
        Handle Error packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Error from %s', addr)
        return

    def handle_ack_error(self, data: bytes, addr: Address) -> None:
        """
        Handle Ack_Error packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Ack_Error from %s', addr)
        return

    def handle_client_update_request(self, data: bytes, addr: Address) -> None:
        """
        Handle Client_Update_Request packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Client_Update_Request from %s', addr)
        return

    def handle_current_server_state(self, data: bytes, addr: Address) -> None:
        """
        Handle Current_Server_State packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Current_Server_State from %s', addr)
        return

    def handle_client_file_request(self, data: bytes, addr: Address) -> None:
        """
        Handle Client_File_Request packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Client_File_Request from %s', addr)
        return

    def handle_file_metadata(self, data: bytes, addr: Address) -> None:
        """
        Handle File_Metadata packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received File_Metadata from %s', addr)
        return

    def handle_ack_metadata(self, data: bytes, addr: Address) -> None:
        """
        Handle Ack_Metadata packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Ack_Metadata from %s', addr)
        return

    def handle_file_upload(self, data: bytes, addr: Address) -> None:
        """
        Handle File_Uplaod packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received File_Upload from %s', addr)
        return

    def handle_file_update(self, data: bytes, addr: Address) -> None:
        """
        Handle File_Update packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received File_Update from %s', addr)
        return

    def handle_ack_upload(self, data: bytes, addr: Address) -> None:
        """
        Handle Ack_Upload packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Ack_Upload from %s', addr)
        return

    def handle_ack_update(self, data: bytes, addr: Address) -> None:
        """
        Handle Ack_Update packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Ack_Update from %s', addr)
        return

    def handle_file_delete(self, data: bytes, addr: Address) -> None:
        """
        Handle File_Delete packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received File_Delete from %s', addr)
        return

    def handle_ack_delete(self, data: bytes, addr: Address) -> None:
        """
        Handle Ack_Delete packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Ack_Delete from %s', addr)
        return

    def handle_file_rename(self, data: bytes, addr: Address) -> None:
        """
        Handle File_Rename packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received File_Rename from %s', addr)
        return

    def handle_ack_rename(self, data: bytes, addr: Address) -> None:
        """
        Handle Ack_Rename packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Ack_Rename from %s', addr)
        return

    def handle_invalid_packet(self, data: bytes, addr: Address) -> None:
        """
        Handle invalid packets, such as with unknown packet types or invalid
        packet hashes.
        Should by overwritten by the child class.
        """
        logging.warning('received and dropped invalid packet from %s', addr)

    def handle_file_update_request(self, data: bytes, addr: Address) -> None:
        """
        Handle File_Update_Request packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received File_Update_Request from %s', addr)
        return

    def handle_file_update_response(self, data: bytes, addr: Address) -> None:
        """
        Handle File_Update_Response packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received File_Update_Response from %s', addr)
        return

    def send_error(self, filename: bytes, filehash: bytes, error_type, error_id: int, description=None, addr=None) -> int:
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
        return self.sendto(data, addr)

    def send_ack_error(self, error_id, addr=None) -> int:
        """
        Pack and send an Ack_Error packet.
        """
        data = b''.join([
            PacketType.Ack_Error,
            error_id.to_bytes(4, byteorder='big')
        ])
        return self.sendto(data, addr)

    def send_client_update_request(self, client_id, addr=None):
        """
        Pack and send a Client_Update_Request packet.
        """
        data = PacketType.Client_Update_Request + client_id.to_bytes(8, byteorder='big')
        return self.sendto(data, addr)

    def send_current_server_state(self, fileinfos, addr=None):
        """
        Pack and send a Current_Server_State packet.
        """
        data = bytearray(PacketType.Current_Server_State)
        for filename, filehash in fileinfos.items():
            data.extend(filehash)
            data.extend((len(filename)).to_bytes(2, byteorder='big'))
            data.extend(filename)
        return self.sendto(data, addr)

    def send_client_file_request(self, filename, filehash, addr=None):
        """
        Pack and send a Client_File_Request packet.
        """

        data = bytearray(PacketType.Client_File_Request)
        data.extend(filehash)
        data.extend((len(filename)).to_bytes(2, byteorder='big'))
        data.extend(filename)

        return self.sendto(data, addr)

    def send_file_metadata(self, filename, fileinfo, addr=None):
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
        return self.sendto(data, addr)

    def send_ack_metadata(self, filehash, filename, upload_id, resume_at_byte=0, addr=None):
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
        return self.sendto(data, addr)

    def send_file_upload(self, upload_id, start_byte, payload, addr=None):
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
        return self.sendto(data, addr)

    def send_file_update(self, update_id, start_byte, payload, addr=None):
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
        return self.sendto(data, addr)

    def send_ack_upload(self, upload_id, acked_bytes, addr=None):
        """
        Pack and send a Ack_Upload packet.
        """
        data = b''.join([
            PacketType.Ack_Upload,
            upload_id.to_bytes(4, byteorder='big'),
            acked_bytes.to_bytes(8, byteorder='big')
        ])
        return self.sendto(data, addr)

    def send_ack_update(self, update_id, acked_bytes, addr=None):
        """
        Pack and send a Ack_Update packet.
        """
        data = b''.join([
            PacketType.Ack_Update,
            update_id.to_bytes(4, byteorder='big'),
            acked_bytes.to_bytes(8, byteorder='big')
        ])
        return self.sendto(data, addr)

    def send_file_delete(self, filehash, filename, addr=None):
        """
        Pack and send a File_Delete packet.
        """
        data = b''.join([
            PacketType.File_Delete,
            filehash,
            (len(filename)).to_bytes(2, byteorder='big'),
            filename
        ])
        return self.sendto(data, addr)

    def send_file_update_request(self, filename, fileinfo, addr=None):
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
        return self.sendto(data, addr)

    def send_file_update_response(self, filename, update_id, start_byte, hashes, addr=None):
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

        return self.sendto(data, addr)

    def send_ack_delete(self, filehash, filename, addr=None):
        """
        Pack and send a Ack_Delete packet.
        """
        data = b''.join([
            PacketType.Ack_Delete,
            filehash,
            (len(filename)).to_bytes(2, byteorder='big'),
            filename
        ])
        return self.sendto(data, addr)

    def send_file_rename(self, filehash, old_filename, new_filename, addr=None):
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
        return self.sendto(data, addr)

    def send_ack_rename(self, filehash: bytes, old_filename, new_filename, addr=None):
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
        return self.sendto(data, addr)

    def sendto(self, data: bytes, addr=None) -> int:
        """
        Calculate and prepend a packet hash for the given data and send it as an
        UDP datagram.
        """

        # add packet hash
        packethash = sha256.hash(data)

        data = packethash + data
        self.transport.sendto(data, addr)

        logging.debug('sent %d bytes', len(data))

        return len(data)

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

    def unpack_client_update_request(self, data: bytes):
        """
        Unpack the Client_Update_Request packet from the given bytes (data).
        """

        if len(data) != 8:
            logging.error("Client_Update_Request didn't have a valid length to parse")
            return (False, None)

        client_id = int.from_bytes(data, byteorder='big')

        logging.info(
            "successfully parsed Client_Update_Request with ClientID %u", client_id)
        return (True, client_id)

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
            logging.error("File_Update_Request packet did not have valid length")
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

        if len(data) < 12 +2:
            logging.error(
                "packet not long enough to contain a filename")
            return (False, None, None, None, None)
        filename_len = int.from_bytes(data[12:14], byteorder='big')

        if len(data) < 12 + 2 + filename_len:
            logging.warning("File_Update_Request did not have valid length")
            return (False, None, None, None, None)
        filename = data[14:14 + filename_len]   

        if len(data) < 12 + 2 + filename_len + 8 + 16:
            logging.warning("File_Update_Response did not contain a valid checksum/hash pair.")
            return (False, None, None, None, None)

        checksums = []
        i = 12 +2 + filename_len
        while i < len(data):
            checksums.append((struct.unpack('>q', data[i:i+8])[0], data[i+8:i+24]))
            i +=24

        return (True, filename, update_id, resume_at_byte, checksums)