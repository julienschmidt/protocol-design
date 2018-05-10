import asyncio
import functools
import os
import signal
import sys
import time

from lib import files
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
        print('received Client_Hello from', addr)
        valid, client_id = self.unpack_client_hello(data)
        if not valid:
            print('received Client_Hallo was not in a correct form, not returning a Server_Hallo')
            return

        print('client wants to connect with clientID:', client_id)
        print('sending server hallo for containing the following file info:', self.fileinfo)

        # respond with Server_Hello
        sent = self.send_server_hello(self.fileinfo, addr)
        print('sent {} bytes back to {}'.format(sent, addr))

    def handle_file_metadata(self, data, addr):
        print('received File_Metadata from', addr)

        valid, filehash, filename, size, permissions, modified_at = self.unpack_file_metadata(
            data)
        if not valid:
            return
        print(sha256.hex(filehash), filename, size,
              oct(permissions), time.ctime(modified_at))

        # TODO: handle size=0 (no upload necessary)

        sent = self.send_ack_metadata(filehash, filename, 42, 0, addr)
        print('sent {} bytes back to {}'.format(sent, addr))

    def handle_file_upload(self, data, addr):
        print('received File_Upload from', addr)

        valid, upload_id, payload_start_byte, payload = self.unpack_file_upload(data)
        if not valid:
            return

        print(upload_id, payload_start_byte, payload)

        sent = self.send_ack_upload(
            upload_id, payload_start_byte + len(payload), addr)
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
