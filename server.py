from os import listdir
from os.path import isfile, join

from lib import sha256
from lib import socket
from lib import packettype

def send(data, addr):
    h = sha256.hash(data)
    print(sha256.hex(h))
    sent = sock.sendto(h + message, addr)

def run(args):
    # bind to UDP socket
    server_address = (args.host, args.port)
    sock = socket.Socket()
    print('storing in', args.path)
    print('starting up on {}:{}\n'.format(*server_address))
    sock.bind(server_address)

    fileinfo = {}

    # list dir
    files = [f for f in listdir(args.path) if isfile(join(args.path, f))]
    for file in files:
        h = sha256.hashFile(file)
        print(file, sha256.hex(h))
        fileinfo[file] = h

    print('\n')

    # wait for messages
    # TODO: make concurrent (use worker threads? asyncio?)
    while True:
        print('\nwaiting to receive message...')
        valid, pt, data, address = sock.recv()
        if not valid:
            print("dropping invalid message")
            continue

        # TODO: use map 'switch'?
        if pt == packettype.Client_Hello:
            print('received Client_Hello from', address)
            if len(data) != 8:
                print('invalid Client_Hello length', len(data))
                continue

            print('clientID:', int.from_bytes(data, byteorder='big'))

            # respond with Server_Hello
            message = bytearray(packettype.Server_Hello)
            for filename, h in fileinfo.items():
                message.extend((len(filename)).to_bytes(2, byteorder='big'))
                message.extend(filename.encode('utf8'))
                message.extend(h)
                print(len(filename), filename, sha256.hex(h))
            sent = sock.sendto(message, address)
            print('sent {} bytes back to {}'.format(sent, address))

        else:
            print('received unknown packet type from', address)
            continue
