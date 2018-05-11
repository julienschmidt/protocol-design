"""
Base for csync protocol implementations.
"""

import asyncio
import logging

from enum import Enum, unique

from . import sha256


@unique
class PacketType(bytes, Enum):
    """
    Csync protocol packet types.
    """
    Error = b'\x00'
    Ack_Error = b'\x01'
    Client_Hello = b'\x10'
    Server_Hello = b'\x11'
    File_Metadata = b'\x20'
    Ack_Metadata = b'\x21'
    File_Upload = b'\x22'
    Ack_Upload = b'\x23'
    File_Delete = b'\x24'
    Ack_Delete = b'\x25'
    File_Rename = b'\x26'
    Ack_Rename = b'\x27'


@unique
class ErrorType(bytes, Enum):
    """
    Csync protocol error types.
    """
    Hash_Error = b'\x00'
    Out_Of_Memory = b'\x01'
    Conflict = b'\x02'


class BaseCsyncProtocol(asyncio.DatagramProtocol):
    """
    Abstract base for csync protocol implementations.
    Provides packing and unpacking of packets.
    """
    # pylint: disable=too-many-public-methods,no-self-use,unused-argument

    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def error_received(self, exc):
        logging.info('error received: {}'.format(exc))

    def datagram_received(self, data, addr):
        logging.info('received {} bytes from {}'.format(len(data), addr))

        # Packet should at least contain the packet hash (32 Bytes) and the packet type (1 Byte)
        if len(data) < 32 + 1:
            self.handle_invalid_packet(data, addr)
            return

        # check packet hash
        packethash = sha256.hash(data[32:])
        if data[:32] != packethash:
            logging.warning("Packet Hash was invalid for packet from {}".format(addr))
            self.handle_invalid_packet(data, addr)
            return

        self.handle_valid_packet(data[32:32 + 1], data[32 + 1:], addr)

    def handle_valid_packet(self, ptype, data, addr):
        """
        Handle valid packets by delegating them to the packet handling methods.
        """
        handle_methods = {
            PacketType.Error: self.handle_error,
            PacketType.Ack_Error: self.handle_ack_error,
            PacketType.Client_Hello: self.handle_client_hello,
            PacketType.Server_Hello: self.handle_server_hello,
            PacketType.File_Metadata: self.handle_file_metadata,
            PacketType.Ack_Metadata: self.handle_ack_metadata,
            PacketType.File_Upload: self.handle_file_upload,
            PacketType.Ack_Upload: self.handle_ack_upload,
            PacketType.File_Delete: self.handle_file_delete,
            PacketType.Ack_Delete: self.handle_ack_delete,
            PacketType.File_Rename: self.handle_file_rename,
            PacketType.Ack_Rename: self.handle_ack_rename,
        }
        func = handle_methods.get(ptype, self.handle_invalid_packet)
        func(data, addr)

    def handle_error(self, data, addr):
        """
        Handle Error packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Error from {}'.format(addr))
        return

    def handle_ack_error(self, data, addr):
        """
        Handle Ack_Error packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Ack_Error from {}'.format(addr))
        return

    def handle_client_hello(self, data, addr):
        """
        Handle Client_Hello packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Client_Hello from {}'.format(addr))
        return

    def handle_server_hello(self, data, addr):
        """
        Handle Server_Hello packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Server_Hello from {}'.format(addr))
        return

    def handle_file_metadata(self, data, addr):
        """
        Handle File_Metadata packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received File_Metadata from {}'.format(addr))
        return

    def handle_ack_metadata(self, data, addr):
        """
        Handle Ack_Metadata packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Ack_Metadata from {}'.format(addr))
        return

    def handle_file_upload(self, data, addr):
        """
        Handle File_Uplaod packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received File_Upload from {}'.format(addr))
        return

    def handle_ack_upload(self, data, addr):
        """
        Handle Ack_Upload packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Ack_Upload from {}'.format(addr))
        return

    def handle_file_delete(self, data, addr):
        """
        Handle File_Delete packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received File_Delete from {}'.format(addr))
        return

    def handle_ack_delete(self, data, addr):
        """
        Handle Ack_Delete packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Ack_Delete from {}'.format(addr))
        return

    def handle_file_rename(self, data, addr):
        """
        Handle File_Rename packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received File_Rename from {}'.format(addr))
        return

    def handle_ack_rename(self, data, addr):
        """
        Handle Ack_Rename packets.
        Should by overwritten by the child class to handle this packet type.
        """
        logging.info('received Ack_Rename from {}'.format(addr))
        return

    def handle_invalid_packet(self, data, addr):
        """
        Handle invalid packets, such as with unknown packet types or invalid
        packet hashes.
        Should by overwritten by the child class.
        """
        logging.warning('Recieved and dropping invalid packet from {}'.format(addr))

    def send_client_hello(self, client_id, addr=None):
        """
        Pack and send a Client_Hello packet.
        """
        data = PacketType.Client_Hello + client_id.to_bytes(8, byteorder='big')
        return self.sendto(data, addr)

    def send_server_hello(self, fileinfos, addr=None):
        """
        Pack and send a Server_Hello packet.
        """
        data = bytearray(PacketType.Server_Hello)
        for filename, filehash in fileinfos.items():
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
        data = (PacketType.File_Metadata +
                filehash +
                (len(filename)).to_bytes(2, byteorder='big') +
                filename +
                size.to_bytes(8, byteorder='big') +
                permissions.to_bytes(2, byteorder='big') +
                modified_at.to_bytes(4, byteorder='big'))
        return self.sendto(data, addr)

    def send_ack_metadata(self, filehash, filename, upload_id, resume_at_byte=0, addr=None):
        """
        Pack and send a Ack_Metadata packet.
        """
        data = (PacketType.Ack_Metadata +
                filehash +
                (len(filename)).to_bytes(2, byteorder='big') +
                filename +
                upload_id.to_bytes(4, byteorder='big') +
                (resume_at_byte.to_bytes(8, byteorder='big') if resume_at_byte > 0 else bytes()))
        return self.sendto(data, addr)

    def send_file_upload(self, upload_id, start_byte, payload, addr=None):
        """
        Pack and send a File_Upload packet.
        """
        data = (PacketType.File_Upload +
                upload_id.to_bytes(4, byteorder='big') +
                start_byte.to_bytes(8, byteorder='big') +
                (len(payload)).to_bytes(2, byteorder='big') +
                payload)
        return self.sendto(data, addr)

    def send_ack_upload(self, upload_id, acked_bytes, addr=None):
        """
        Pack and send a Ack_Upload packet.
        """
        data = (PacketType.Ack_Upload +
                upload_id.to_bytes(4, byteorder='big') +
                acked_bytes.to_bytes(8, byteorder='big'))
        return self.sendto(data, addr)

    def send_file_delete(self, filehash, filename, addr=None):
        """
        Pack and send a File_Delete packet.
        """
        data = (PacketType.File_Delete +
                filehash +
                (len(filename)).to_bytes(2, byteorder='big') +
                filename)
        return self.sendto(data, addr)

    def send_ack_delete(self, filehash, filename, addr=None):
        """
        Pack and send a Ack_Delete packet.
        """
        data = (PacketType.Ack_Delete +
                filehash +
                (len(filename)).to_bytes(2, byteorder='big') +
                filename)
        return self.sendto(data, addr)

    def send_file_rename(self, filehash, old_filename, new_filename, addr=None):
        """
        Pack and send a File_Rename packet.
        """
        data = (PacketType.File_Rename +
                filehash +
                (len(old_filename)).to_bytes(2, byteorder='big') +
                old_filename +
                (len(new_filename)).to_bytes(2, byteorder='big') +
                new_filename)
        return self.sendto(data, addr)

    def send_ack_rename(self, filehash, old_filename, new_filename, addr=None):
        """
        Pack and send a Ack_Rename packet.
        """
        data = (PacketType.Ack_Rename +
                filehash +
                (len(old_filename)).to_bytes(2, byteorder='big') +
                old_filename +
                (len(new_filename)).to_bytes(2, byteorder='big') +
                new_filename)
        return self.sendto(data, addr)

    def sendto(self, data, addr=None):
        """
        Calculate and prepend a packet hash for the given data and send it as an
        UDP datagram.
        """

        # add packet hash
        packethash = sha256.hash(data)

        data = packethash + data
        self.transport.sendto(data, addr)

        logging.debug('Did Sent {} bytes'.format(len(data)))

        return len(data)

    def unpack_filehash_and_name(self, data):
        """
        Unpack packet and extract a filehash (32 Bytes) and a file name of variable length (2 Bytes length determiner) + Bytes to store name
        Returning a tuple containing (Success (Bool), Remaining Data in File (Bytes), File Hash (Bytes), Filename (Bytes))
s
        TODO: Add Table of example message

        """

        if len(data) < 32 + 2: # Check if the data packet at least stores enough data to store the hash (32 Bytes) and filename length (2 Bytes)
            logging.error("Packet did not have valid length to incorporate "
                          "a filehash and name or did not contain all information")
            return (False, None, None)

        # Parse filehash and filename length
        filehash = data[:32]
        filename_len = int.from_bytes(data[32:34], byteorder='big')

        if len(data) < 32 + 2 + filename_len:
            logging.error("Packet did not have valid length to incorporate "
                          "a filehash and name or did not contain all information")
            return (False, None, None, None)

        filename = data[34:34 + filename_len]
        data = data[34 + filename_len:]

        return (False, data, filehash, filename)

    def unpack_client_hello(self, data):
        """
        Unpack the Client_Hello packet from the given bytes (data).

        TODO: Client_Hello description

        """

        if len(data) != 8:
            logging.error("CLient Hello didn't have a  valid length to parse")
            return (False, None)

        client_id = int.from_bytes(data, byteorder='big')

        logging.info("Did successfully parse Client Hello with Client ID {}".format(client_id))
        return (True, client_id)

    def unpack_server_hello(self, data):
        """
        Unpack the Server_Hello packet from the given bytes (data).

        TODO: Server_Hello description

        """

        remote_files = {}
        while len(data) > 2 + 32: # Min 2 Bytes for file filename_len and 32 Bytes for Hash
            valid, data, filehash, filename = self.unpack_filehash_and_name(data)
            if not valid:
                logging.error("Server Hello not valid length to parse "
                              "filehash and filename of one file")
                return (False, None)
            remote_files[filename] = filehash

        if len(data) != 0:
            logging.error("Server Hello did not have valid length, "
                          "there is data left after parsing all files")
            return (False, {})

        logging.info("Did successfully parse Server Hello: {}".format(remote_files))
        return (True, remote_files)

    def unpack_file_metadata(self, data):
        """
        Unpack the File_Metadata packet from the given bytes (data).

        TODO: File_Metadata description

        """

        # Parse filehash and filename
        valid, data, filehash, filename = self.unpack_filehash_and_name(data)

        if not valid:
            logging.error("File Metadata Packet did not have valid length or "
                          "did not contain all information to parse filehash and filename")
            return (False, None, None, None, None, None)


        # Check if the data packet stores enough data to store the size (8 Bytes),
        # permissions (2 Bytes), and modified_at date (4 Bytes)
        if len(data) != 8 + 2 + 4:
            logging.error("File Metadata Packet did not have valid length or "
                          "did not contain all information after checking filename length")
            return (False, None, None, None, None, None)

        # Parse filesize, permissions and modified_at
        filesize = int.from_bytes(data[:8], byteorder='big')
        permissions = int.from_bytes(data[8:10], byteorder='big')
        modified_at = int.from_bytes(data[10:14], byteorder='big')

        logging.info("Did successfully parse File Metadata of file named {} "
                     "(Hash: {}). Filesize: {}, Permissions: {}, Modified last at: {}"
                     .format(filename, filehash, filesize, permissions, modified_at))
        return (True, filehash, filename, filesize, permissions, modified_at)

    def unpack_ack_metadata(self, data):
        """
        Unpack the Ack_Metadata packet from the given bytes (data).

        TODO: File_Metadata description

        """

        # Parse filehash and filename
        valid, data, filehash, filename = self.unpack_filehash_and_name(data)

        if not valid:
            logging.error("File Metadata Ack Packet did not have valid length or did "
                          "not contain all information to parse filehash and filename")
            return (False, None, None, None, None)


        # Check if the data packet stores enough data to store the upload_id (4 Bytes)
        if len(data) == 4 or len(data) == 4 + 8:
            logging.error("File Metadata Ack Packet did not have valid length or did "
                          "not contain all information to parse `upload_id` or `upload_id` and `resume_at_byte`")
            return (False, None, None, None, None)

        # Parse upload_id and possibly resume_at_byte
        upload_id = int.from_bytes(data[:4], byteorder='big')
        resume_at_byte = int.from_bytes( data[4:12], byteorder='big') if len(data) == 4 + 8 else 0

        logging.info("Did successfully parse File Metadata Ack of file named {} (Hash: {}). "
                     "The Upload ID is {} and upload shoud resume at the {}. Byte"
                     .format(filename, filehash, upload_id, resume_at_byte))
        return (True, filehash, filename, upload_id, resume_at_byte)

    def unpack_file_upload(self, data):
        """
        Unpack the File_Upload packet from the given bytes (data).

        TODO: File_Upload description

        """

        # Check if the data packet stores enough data to at least store the upload_id (4 Bytes),
        # payload_start_byte (8 Bytes) and the payload_len (2 Bytes)
        if len(data) < 4 + 8 + 2:
            logging.error("File Upload Packet did not have valid length or did not contain all "
                          "information to parse `upload_id`, `payload_start_byte` and `payload_len`")
            return (False, None, None, None)

        upload_id = int.from_bytes(data[:4], byteorder='big')
        payload_start_byte = int.from_bytes(data[4:12], byteorder='big')
        payload_len = int.from_bytes(data[12:14], byteorder='big')
        data = data[4 + 8 + 2:]

        if len(data) != payload_len:
            logging.error("File Metadate Ack Packet did not have valid length or did not contain all "
                          "information to parse `upload_id`, `payload_start_byte` and `payload_len`")
            return (False, None, None, None)
        payload = data

        logging.info("Did successfully parse File Upload for Upload ID: {}. "
                     "The Payload starts at the {}. Byte and is {}"
                     .format(upload_id, payload_start_byte, payload))
        return (True, upload_id, payload_start_byte, payload)

    def unpack_ack_upload(self, data):
        """
        Unpack the Ack_Upload packet from the given bytes (data).

        TODO: File_Upload_Ack description

        """

        # Check if the data packet stores enough data to at least store the upload_id (4 Bytes) and the acked_bytes (8 Bytes)
        if len(data) != 4 + 8:
            logging.error("File Metadate Ack Packet did not have valid length or did not contain all "
                          "information to parse `upload_id` and `acked_bytes`")
            return (False, None, None)

        upload_id = int.from_bytes(data[:4], byteorder='big')
        acked_bytes = int.from_bytes(data[4:12], byteorder='big')

        logging.info("Did successfully parse File Upload Ack for Upload ID: {}. "
                     "Acknowledged all bytes until the {}. Byte"
                     .format(upload_id, acked_bytes))
        return (True, upload_id, acked_bytes)

    def unpack_file_delete(self, data):
        """
        Unpack the File_Delete packet from the given bytes (data).

        TODO: File_Delete description

        """

        # Parse filehash and filename
        valid, data, filehash, filename = self.unpack_filehash_and_name(data)

        if not valid or len(data) != 0:
            logging.error("File Delete Packet did not have valid length or "
                          "did not contain all information to parse filehash and filename")
            return (False, None, None)

        logging.info("Did successfully parse File Delete of file named {} (Hash: {})."
                     .format(filename, filehash))
        return (True, filehash, filename)

    def unpack_ack_delete(self, data):
        """
        Unpack the Ack_Delete packet from the given bytes (data).

        TODO: File_Delete_Ack description

        """

        # Parse filehash and filename
        valid, data, filehash, filename = self.unpack_filehash_and_name(data)

        if not valid or len(data) != 0:
            logging.error("File Delete Packet Ack did not have valid length or "
                          "did not contain all information to parse filehash and filename")
            return (False, None, None)

        logging.info("Did successfully parse File Delete Ack of file named {} (Hash: {})."
                     .format(filename, filehash))
        return (True, filehash, filename)

    def unpack_file_rename(self, data):
        """
        Unpack the File_Rename packet from the given bytes (data).

        TODO: File_Rename description

        """

        # Parse filehash and filename
        valid, data, filehash, old_filename = self.unpack_filehash_and_name(data)

        if not valid or len(data) <= 2:
            logging.error("File Rename Packet did not have valid length or "
                          "did not contain all information to parse filehash and filename")
            return (False, None, None)


        new_filename_len = int.from_bytes(data[:2], byteorder='big')
        if len(data) != new_filename_len:
            logging.error("File Rename Packet did not have valid length to contain all information to parse the new filename")
            return (False, None, None)

        new_filename = data[2:2 + new_filename_len]

        logging.info("Did successfully parse File Rename of file currently named {} (Hash: {})."
                     "Should be renamed to {}"
                     .format(old_filename, filehash, new_filename))
        return (True, filehash, old_filename, new_filename)

    def unpack_ack_rename(self, data):
        """
        Unpack the Ack_Rename packet from the given bytes (data).

        TODO: File_Rename_Ack description

        """

        # Parse filehash and filename
        valid, data, filehash, old_filename = self.unpack_filehash_and_name(data)

        if not valid or len(data) <= 2:
            logging.error("File Rename Packet Ack did not have valid length or "
                          "did not contain all information to parse filehash and filename")
            return (False, None, None)

        new_filename_len = int.from_bytes(data[:2], byteorder='big')
        if len(data) != new_filename_len:
            logging.error(
                "File Rename Packet Ack did not have valid length to contain all information to parse the new filename")
            return (False, None, None)

        new_filename = data[2:2 + new_filename_len]

        logging.info("Did successfully parse File Rename Ack of file currently named {} (Hash: {})."
                     "Should be renamed to {}"
                     .format(old_filename, filehash, new_filename))
        return (True, filehash, old_filename, new_filename)
