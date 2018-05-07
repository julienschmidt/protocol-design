import random

from lib import socket
from lib import sha256
from lib import packettype

def run(args):
    # generate client ID
    clientID = random.getrandbits(64)
    print("clientID:", clientID)

    # create UDP socket
    server_address = (args.host, args.port)
    sock = socket.Socket()

    print("sending Client Hello...")
    message = packettype.Client_Hello + clientID.to_bytes(8, byteorder='big')
    sent = sock.sendto(message, server_address)


    # wait for Server Hello
    print("awaiting Server Hello...")
    valid, pt, data, address = sock.recv()
    if not valid or pt != packettype.Server_Hello:
        print("Invalid response. Aborting!")
        sock.close()
        return

    while len(data) > 34:
        l = int.from_bytes(data[:2], byteorder='big')
        print("len", l)
        # TODO: verify data len
        print("filename", data[2:2+l])
        data = data[2+l:]
        print("filehash", sha256.hex(data[:32]))
        data = data[32:]
    # TODO: verify len(data) == 0
