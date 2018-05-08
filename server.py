import asyncio
import functools
import os
import signal
import sys

from lib import files
from lib import packettype
from lib import sha256
from lib.protocol import BaseCsyncProtocol


class ServerCsyncProtocol(BaseCsyncProtocol):
    def __init__(self, loop, path):
        super(ServerCsyncProtocol, self).__init__();
        self.loop = loop
        self.path = path

        print('storing in', path)

        self.fileinfo = {}
        # list dir
        local_files = files.list(path)
        for file in local_files:
            h = sha256.hash_file(self.path+file)
            print(file, sha256.hex(h))
            self.fileinfo[file.encode('utf8')] = h
        print('\n')

    def handle_client_hello(self, data, addr):
        print('received Client_Hello from', addr)
        if len(data) != 8:
            print('invalid Client_Hello length', len(data))
            return

        print('clientID:', int.from_bytes(data, byteorder='big'))

        # respond with Server_Hello
        message = bytearray(packettype.Server_Hello)
        for filename, h in self.fileinfo.items():
            message.extend((len(filename)).to_bytes(2, byteorder='big'))
            message.extend(filename)
            message.extend(h)
            print(len(filename), filename, sha256.hex(h))
        sent = self.sendto(message, addr)
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
