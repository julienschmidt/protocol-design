import asyncio
import functools
import os
import random
import signal
import sys
import time

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from lib import files
from lib import packettype
from lib import sha256
from lib.protocol import BaseCsyncProtocol


class FileEventHandler(FileSystemEventHandler):
    def __init__(self, loop, protocol):
        self.loop = loop
        self.protocol = protocol

    def on_created(self, event):
        if event.is_directory:
            return

        self.loop.call_soon_threadsafe(self.protocol.upload_file,
            event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return

        self.loop.call_soon_threadsafe(self.protocol.delete_file,
            event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return

        self.loop.call_soon_threadsafe(self.protocol.update_file,
            event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return

        self.loop.call_soon_threadsafe(self.protocol.move_file,
            event.src_path, event.dest_path)


class ClientCsyncProtocol(BaseCsyncProtocol):
    def __init__(self, loop, path):
        super(ClientCsyncProtocol, self).__init__();
        self.loop = loop
        self.path = path

        # generate client ID
        self.id = random.getrandbits(64)
        print("clientID:", self.id)
        print('syncing path', self.path)

    def connection_made(self, transport):
        super(ClientCsyncProtocol, self).connection_made(transport);
        self.loop.call_later(0.1, self.start)

    def start(self):
        print("sending Client Hello...")
        message = packettype.Client_Hello + self.id.to_bytes(8, byteorder='big')
        sent = self.sendto(message)

        print("awaiting Server Hello...\n")

    def handle_server_hello(self, data, addr):
        print("received Server Hello:")
        remote_files = {}
        while len(data) > 34:
            l = int.from_bytes(data[:2], byteorder='big')
            print("len", l)
            # TODO: verify data len
            filename = data[2:2+l]
            print("filename", filename)
            data = data[2+l:]
            filehash = data[:32]
            print("filehash", sha256.hex(filehash))
            data = data[32:]
            remote_files[filename] = filehash
        # TODO: verify len(data) == 0

        # start file dir observer
        event_handler = FileEventHandler(self.loop, self)
        self.observer = Observer()
        self.observer.schedule(event_handler, self.path, recursive=False)
        self.observer.start()

        # build file dir diff
        local_files = files.list(self.path)
        for file in local_files:
            h = sha256.hashFile(file)
            if file not in remote_files:
                self.loop.call_soon(self.upload_file, file)
            elif h != remote_files[file]:
                self.loop.call_soon(self.update_file, file)
        print('\n')

    def upload_file(self, path):
        #sha256.hashFile(path)
        print("upload", path)

    def delete_file(self, path):
        print("delete", path)

    def update_file(self, path):
        #sha256.hashFile(path)
        print("update", path)

    def move_file(self, old_path, new_path):
        #sha256.hashFile(new_path)
        print("move", old_path, "to", new_path)


    def connection_lost(self, exc):
        print("Socket closed, stop the event loop")
        self.stop()

    def signal(self, signame):
        print("got signal %s: exit" % signame)
        self.stop()

    def stop(self):
        self.loop.stop()
        if self.observer:
            self.observer.stop()


def run(args):
    loop = asyncio.get_event_loop()

    # create UDP socket
    server_address = (args.host, args.port)
    print(server_address)
    connect = loop.create_datagram_endpoint(
        lambda: ClientCsyncProtocol(loop, args.path),
        remote_addr=server_address)
    transport, protocol = loop.run_until_complete(connect)

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
