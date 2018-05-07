import socket

from . import packettype
from . import sha256

class Socket:
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def bind(self, addr):
        self.s.bind(addr)

    def close(self):
        self.s.close()

    def recv(self):
        data, addr = self.s.recvfrom(4096)
        valid = False

        print('received {} bytes from {}'.format(len(data), addr))
        if len(data) < 33:
            return (False, packettype.Error, data, addr)

        # check packet hash
        h = sha256.hash(data[32:])
        if data[:32] != h:
            print('dropping message with bad hash, is: {} should be: {}'.format(sha256.hex(h), sha256.hex(data[:32])))
            return (False, packettype.Error, data, addr)

        return (True, data[32:33], data[33:], addr)

    # first byte must be the packet type
    def sendto(self, data, addr):
        # add packet hash
        h = sha256.hash(data)
        print(sha256.hex(h))

        data = h + data
        #print("Sending:", len(data), data)
        sent = self.s.sendto(data, addr)
        return sent
