import asyncio
import stat

from enum import Enum, unique

from . import sha256


@unique
class PacketType(bytes, Enum):
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
class ErrorType(Enum):
    Hash_Error = b'\x00'
    Out_Of_Memory = b'\x01'
    Conflict = b'\x02'

class BaseCsyncProtocol(asyncio.DatagramProtocol):

    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def error_received(self, exc):
        print('error received:', exc)

    def datagram_received(self, data, addr):
        print('received {} bytes from {}'.format(len(data), addr))
        if len(data) < 33:
            self.handle_invalid_packet(data, addr)
            return

        # check packet hash
        h = sha256.hash(data[32:])
        if data[:32] != h:
            self.handle_invalid_packet(data, addr)
            return

        self.handle_valid_packet(data[32:33], data[33:], addr)

    def handle_valid_packet(self, ptype, data, addr):
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
        print('received Error from', addr)
        return

    def handle_ack_error(self, data, addr):
        print('received Ack_Error from', addr)
        return

    def handle_client_hello(self, data, addr):
        print('received Client_Hello from', addr)
        return

    def handle_server_hello(self, data, addr):
        print('received Server_Hello from', addr)
        return

    def handle_file_metadata(self, data, addr):
        print('received File_Metadata from', addr)
        return

    def handle_ack_metadata(self, data, addr):
        print('received Ack_Metadata from', addr)
        return

    def handle_file_upload(self, data, addr):
        print('received File_Upload from', addr)
        return

    def handle_ack_upload(self, data, addr):
        print('received Ack_Upload from', addr)
        return

    def handle_file_delete(self, data, addr):
        print('received File_Delete from', addr)
        return

    def handle_ack_delete(self, data, addr):
        print('received Ack_Delete from', addr)
        return

    def handle_file_rename(self, data, addr):
        print('received File_Rename from', addr)
        return

    def handle_ack_rename(self, data, addr):
        print('received Ack_Rename from', addr)
        return

    def handle_invalid_packet(self, data, addr):
        print('dropping invalid packet from {}'.format(addr))

    def send_client_hello(self, client_id, addr=None):
        data = PacketType.Client_Hello + client_id.to_bytes(8, byteorder='big')
        return self.sendto(data, addr)

    def send_server_hello(self, fileinfos, addr=None):
        data = bytearray(PacketType.Server_Hello)
        for filename, filehash in fileinfos.items():
            data.extend((len(filename)).to_bytes(2, byteorder='big'))
            data.extend(filename)
            data.extend(filehash)
            print(len(filename), filename, sha256.hex(filehash))
        return self.sendto(data, addr)

    def send_file_metadata(self, filehash, filename, statinfo, addr=None):
        data = (PacketType.File_Metadata +
                filehash +
                (len(filename)).to_bytes(2, byteorder='big') +
                filename +
                statinfo[stat.ST_SIZE].to_bytes(8, byteorder='big') +
                (statinfo[stat.ST_MODE] & 0o777).to_bytes(2, byteorder='big') +
                statinfo[stat.ST_MTIME].to_bytes(4, byteorder='big'))
        return self.sendto(data, addr)

    def send_ack_metadata(self, filehash, filename, upload_id, resume_at_byte=0, addr=None):
        data = (PacketType.Ack_Metadata +
                filehash +
                (len(filename)).to_bytes(2, byteorder='big') +
                filename +
                upload_id.to_bytes(4, byteorder='big') +
                (resume_at_byte.to_bytes(8, byteorder='big') if resume_at_byte > 0 else bytes()))
        return self.sendto(data, addr)

    def send_file_upload(self, upload_id, start_byte, payload, addr=None):
        data = (PacketType.File_Upload +
                upload_id.to_bytes(4, byteorder='big') +
                start_byte.to_bytes(8, byteorder='big') +
                (len(payload)).to_bytes(2, byteorder='big') +
                payload)
        return self.sendto(data, addr)

    def send_ack_upload(self, upload_id, acked_bytes, addr=None):
        data = (PacketType.Ack_Upload +
                upload_id.to_bytes(4, byteorder='big') +
                acked_bytes.to_bytes(8, byteorder='big'))
        return self.sendto(data, addr)

    def send_file_delete(self, filehash, filename, addr=None):
        data = (PacketType.File_Delete +
                filehash +
                (len(filename)).to_bytes(2, byteorder='big') +
                filename)
        return self.sendto(data, addr)

    def send_ack_delete(self, filehash, filename, addr=None):
        data = (PacketType.Ack_Delete +
                filehash +
                (len(filename)).to_bytes(2, byteorder='big') +
                filename)
        return self.sendto(data, addr)

    def send_file_delete(self, filehash, old_filename, new_filename, addr=None):
        data = (PacketType.File_Rename +
                filehash +
                (len(old_filename)).to_bytes(2, byteorder='big') +
                old_filename +
                (len(new_filename)).to_bytes(2, byteorder='big') +
                new_filename)
        return self.sendto(data, addr)

    def send_ack_delete(self, filehash, old_filename, new_filename, addr=None):
        data = (PacketType.Ack_Rename +
                filehash +
                (len(old_filename)).to_bytes(2, byteorder='big') +
                old_filename +
                (len(new_filename)).to_bytes(2, byteorder='big') +
                new_filename)
        return self.sendto(data, addr)

    # first byte must be the packet type
    def sendto(self, data, addr=None):
        # add packet hash
        packethash = sha256.hash(data)
        #print('sending packet with packethash: ', sha256.hex(packethash))

        data = packethash + data
        # print("sending packet with length:", len(data), 'containing the following data' ,data)
        self.transport.sendto(data, addr)
        return len(data)

    def unpack_client_hello(self, data):
        if len(data) != 8:
            return (False, 0)
        return (True, int.from_bytes(data, byteorder='big'))

    def unpack_server_hello(self, data):
        remote_files = {}
        while len(data) > 34:
            l = int.from_bytes(data[:2], byteorder='big')
            print("len", l)
            # TODO: verify data len
            filename = data[2:2 + l]
            print("filename", filename)
            data = data[2 + l:]
            filehash = data[:32]
            print("filehash", sha256.hex(filehash))
            data = data[32:]
            remote_files[filename] = filehash
        # TODO: verify len(data) == 0
        return (True, remote_files)

    def unpack_file_metadata(self, data):
        filehash = data[:32]
        filename_len = int.from_bytes(data[32:34], byteorder='big')
        filename = data[34:34 + filename_len]
        data = data[34 + filename_len:]
        size = int.from_bytes(data[:8], byteorder='big')
        permissions = int.from_bytes(data[8:10], byteorder='big')
        modified_at = int.from_bytes(data[10:14], byteorder='big')
        return (True, filehash, filename, size, permissions, modified_at)

    def unpack_ack_metadata(self, data):
        filehash = data[:32]
        filename_len = int.from_bytes(data[32:34], byteorder='big')
        filename = data[34:34 + filename_len]
        data = data[34 + filename_len:]
        upload_id = int.from_bytes(data[:4], byteorder='big')
        resume_at_byte = int.from_bytes(
            data[4:12], byteorder='big') if len(data) >= 12 else 0
        return (True, filehash, filename, upload_id, resume_at_byte)

    def unpack_file_upload(self, data):
        upload_id = int.from_bytes(data[:4], byteorder='big')
        payload_start_byte = int.from_bytes(data[4:12], byteorder='big')
        payload_len = int.from_bytes(data[12:14], byteorder='big')
        payload = data[14:14 + payload_len]
        return (True, upload_id, payload_start_byte, payload)

    def unpack_ack_upload(self, data):
        upload_id = int.from_bytes(data[:4], byteorder='big')
        acked_bytes = int.from_bytes(data[4:12], byteorder='big')
        return (True, upload_id, acked_bytes)

    def unpack_file_delete(self, data):
        filehash = data[:32]
        filename_len = int.from_bytes(data[32:34], byteorder='big')
        filename = data[34:34 + filename_len]
        return (True, filehash, filename)

    def unpack_ack_delete(self, data):
        filehash = data[:32]
        filename_len = int.from_bytes(data[32:34], byteorder='big')
        filename = data[34:34 + filename_len]
        return (True, filehash, filename)

    def unpack_file_rename(self, data):
        filehash = data[:32]
        old_filename_len = int.from_bytes(data[32:34], byteorder='big')
        old_filename = data[34:34 + old_filename_len]
        data = data[34 + old_filename_len:]
        new_filename_len = int.from_bytes(data[:2], byteorder='big')
        new_filename = data[2:2 + new_filename_len]
        return (True, filehash, old_filename, new_filename)

    def unpack_ack_rename(self, data):
        filehash = data[:32]
        old_filename_len = int.from_bytes(data[32:34], byteorder='big')
        old_filename = data[34:34 + old_filename_len]
        data = data[34 + old_filename_len:]
        new_filename_len = int.from_bytes(data[:2], byteorder='big')
        new_filename = data[2:2 + new_filename_len]
        return (True, filehash, old_filename, new_filename)
