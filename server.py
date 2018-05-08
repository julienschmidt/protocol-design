import asyncio
import functools
import os
import signal
import sys
import time

from lib import files
from lib import packettype
from lib import sha256
from lib.protocol import BaseCsyncProtocol


class ServerCsyncProtocol(BaseCsyncProtocol):

    def __init__(self, loop, path):
        super(ServerCsyncProtocol, self).__init__()
        self.loop = loop
        self.path = path

        print('storing in', path)

        self.fileinfo = {}
        # list dir
        local_files = files.list(path)
        for file in local_files:
            filehash = sha256.hash_file(self.path + file)
            print(file, sha256.hex(filehash))
            self.fileinfo[file.encode('utf8')] = filehash
        print('\n')

    def handle_client_hello(self, data, addr):
        if len(data) != 8:
            print('invalid Client_Hello length', len(data))
            return

        print('clientID:', int.from_bytes(data, byteorder='big'))

        # respond with Server_Hello
        sent = self.send_server_hello(self.fileinfo, addr)
        print('sent {} bytes back to {}'.format(sent, addr))

    def handle_file_metadata(self, data, addr):
        filehash = data[:32]
        filename_len = int.from_bytes(data[32:34], byteorder='big')
        filename = data[34:34 + filename_len]
        data = data[34 + filename_len:]
        size = int.from_bytes(data[:8], byteorder='big')
        permissions = int.from_bytes(data[8:10], byteorder='big')
        modified_at = int.from_bytes(data[10:14], byteorder='big')
        print(sha256.hex(filehash), filename_len, filename,
              size, oct(permissions), time.ctime(modified_at))

        # TODO: handle size=0 (no upload necessary)

        sent = self.send_ack_metadata(filehash, filename, 42, 0, addr)
        print('sent {} bytes back to {}'.format(sent, addr))

    def handle_file_upload(self, data, addr):
        upload_id = int.from_bytes(data[:4], byteorder='big')
        payload_start_byte = int.from_bytes(data[4:12], byteorder='big')
        payload_len = int.from_bytes(data[12:14], byteorder='big')
        payload = data[14:14+payload_len]

        print(upload_id, payload_start_byte, payload_len, payload)

        sent = self.send_ack_upload(upload_id, payload_start_byte+payload_len, addr)
        print('sent {} bytes back to {}'.format(sent, addr))

    def signal(self, signame):
        print("got signal %s: exit" % signame)
        self.loop.stop()


def run(args):
    loop = asyncio.get_event_loop()

    # bind to UDP socket
    print("Starting UDP server")
    server_address = (args.host, args.port)
    print('starting up on {}:{}\n'.format(*server_address))
    listen = loop.create_datagram_endpoint(
        lambda: ServerCsyncProtocol(loop, args.path),
        local_addr=server_address)
    transport, protocol = loop.run_until_complete(listen)

    if sys.platform != 'win32':
        for signame in ('SIGINT', 'SIGTERM'):
            loop.add_signal_handler(getattr(signal, signame),
                                    functools.partial(protocol.signal, signame))

    print("Event loop running forever, press Ctrl+C to interrupt.")
    print("pid %s: send SIGINT or SIGTERM to exit.\n\n" % os.getpid())

    try:
        loop.run_forever()
    finally:
        transport.close()
        loop.close()
