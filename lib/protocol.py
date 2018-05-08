import asyncio

from . import packettype
from . import sha256

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
            packettype.Error: self.handle_error,
            packettype.Ack_Error: self.handle_ack_error,
            packettype.Client_Hello: self.handle_client_hello,
            packettype.Server_Hello: self.handle_server_hello,
            packettype.File_Metadata: self.handle_file_metadata,
            packettype.Ack_Metadata: self.handle_ack_metadata,
            packettype.File_Upload: self.handle_file_upload,
            packettype.Ack_Upload: self.handle_ack_upload,
            packettype.File_Delete: self.handle_file_delete,
            packettype.Ack_Delete: self.handle_ack_delete,
        }
        func = handle_methods.get(ptype, self.handle_invalid_packet)
        func(data, addr)

    def handle_error(self, data, addr):
        return

    def handle_ack_error(self, data, addr):
        return

    def handle_client_hello(self, data, addr):
        return

    def handle_server_hello(self, data, addr):
        return

    def handle_file_metadata(self, data, addr):
        return

    def handle_ack_metadata(self, data, addr):
        return

    def handle_file_upload(self, data, addr):
        return

    def handle_ack_upload(self, data, addr):
        return

    def handle_file_delete(self, data, addr):
        return

    def handle_ack_delete(self, data, addr):
        return

    def handle_invalid_packet(self, data, addr):
        print('dropping invalid packet from {}'.format(addr))


    def send_client_hello(self, client_id, addr=None):
        data = packettype.Client_Hello + client_id.to_bytes(8, byteorder='big')
        return self.sendto(data, addr)

    def send_server_hello(self, fileinfos, addr=None):
        data = bytearray(packettype.Server_Hello)
        for filename, filehash in fileinfos.items():
            data.extend((len(filename)).to_bytes(2, byteorder='big'))
            data.extend(filename)
            data.extend(filehash)
            print(len(filename), filename, sha256.hex(filehash))
        return self.sendto(data, addr)

    # first byte must be the packet type
    def sendto(self, data, addr=None):
        # add packet hash
        h = sha256.hash(data)
        print(sha256.hex(h))

        data = h + data
        #print("Sending:", len(data), data)
        self.transport.sendto(data, addr)
        return len(data)
