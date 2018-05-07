import asyncio
import random

from lib import packettype
from lib import sha256
from lib.protocol import BaseCsyncProtocol


class ClientCsyncProtocol(BaseCsyncProtocol):
    def __init__(self, loop):
        super(ClientCsyncProtocol, self).__init__();
        self.loop = loop

        # generate client ID
        self.id = random.getrandbits(64)
        print("clientID:", self.id)

    def connection_made(self, transport):
        super(ClientCsyncProtocol, self).connection_made(transport);

        print("sending Client Hello...")
        message = packettype.Client_Hello + self.id.to_bytes(8, byteorder='big')
        sent = self.sendto(message)

        print("awaiting Server Hello...")

    def handle_server_hello(self, data, addr):
        print("received Server Hello:")
        while len(data) > 34:
            l = int.from_bytes(data[:2], byteorder='big')
            print("len", l)
            # TODO: verify data len
            print("filename", data[2:2+l])
            data = data[2+l:]
            print("filehash", sha256.hex(data[:32]))
            data = data[32:]
        # TODO: verify len(data) == 0

    def connection_lost(self, exc):
        print("Socket closed, stop the event loop")
        loop = asyncio.get_event_loop()
        loop.stop()


def run(args):
    loop = asyncio.get_event_loop()

    # create UDP socket
    server_address = (args.host, args.port)
    print(server_address)
    connect = loop.create_datagram_endpoint(
        lambda: ClientCsyncProtocol(loop),
        remote_addr=server_address)
    transport, protocol = loop.run_until_complete(connect)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    transport.close()
    loop.close()
