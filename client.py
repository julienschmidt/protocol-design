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

    def __init__(self, loop, path, protocol):
        self.loop = loop
        self.path = path
        self.protocol = protocol

    def relative_filepath(self, file):
        return files.relative_path(file, self.path)

    def on_created(self, event):
        if event.is_directory:
            return

        self.loop.call_soon_threadsafe(self.protocol.upload_file,
                                       self.relative_path(event.src_path))

    def on_deleted(self, event):
        if event.is_directory:
            return

        self.loop.call_soon_threadsafe(self.protocol.delete_file,
                                       self.relative_path(event.src_path))

    def on_modified(self, event):
        if event.is_directory:
            return

        self.loop.call_soon_threadsafe(self.protocol.update_file,
                                       self.relative_path(event.src_path))

    def on_moved(self, event):
        if event.is_directory:
            return

        self.loop.call_soon_threadsafe(self.protocol.move_file,
                                       self.relative_path(event.src_path),
                                       self.relative_path(event.dest_path))


class ClientCsyncProtocol(BaseCsyncProtocol):

    def __init__(self, loop, path):
        super(ClientCsyncProtocol, self).__init__()
        self.loop = loop
        self.path = path
        self.observer = None

        # generate client ID
        self.id = random.getrandbits(64)
        print("clientID:", self.id)
        print('syncing path', self.path)

    # Socket State
    def connection_made(self, transport):
        super(ClientCsyncProtocol, self).connection_made(transport)
        self.loop.call_later(0.001, self.start)

    def connection_lost(self, exc):
        print("Socket closed, stop the event loop")
        self.stop()

    # UNIX Signals
    def signal(self, signame):
        print("got signal %s: exit" % signame)
        self.stop()

    # State
    def start(self):
        print("sending Client Hello...")
        sent = self.send_client_hello(self.id)
        print('sent {} bytes'.format(sent))

        print("awaiting Server Hello...\n")

    def stop(self):
        self.loop.stop()
        if self.observer:
            self.observer.stop()

    # Packet Handlers
    def handle_server_hello(self, data, addr):
        print("received Server Hello:")
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

        # start file dir observer
        event_handler = FileEventHandler(self.loop, self.path, self)
        self.observer = Observer()
        self.observer.schedule(event_handler, self.path, recursive=False)
        self.observer.start()

        # build file dir diff
        local_files = files.list(self.path)
        for file in local_files:
            filehash = sha256.hash_file(self.path + file)
            filepath = file.encode('utf8')
            if filepath not in remote_files:
                self.loop.call_soon(self.upload_file, filepath, filehash)
            elif filehash != remote_files[filepath]:
                self.loop.call_soon(self.update_file, filepath, filehash)
        print('\n')

    def handle_ack_metadata(self, data, addr):
        print('received Ack_Metadata from', addr)

        filehash = data[:32]
        filename_len = int.from_bytes(data[32:34], byteorder='big')
        filename = data[34:34 + filename_len]
        data = data[34 + filename_len:]
        upload_id = int.from_bytes(data[:4], byteorder='big')
        resume_at_byte = int.from_bytes(
            data[4:12], byteorder='big') if len(data) >= 12 else 0
        print(sha256.hex(filehash), filename_len,
              filename, upload_id, resume_at_byte)

        sent = self.send_file_upload(upload_id, resume_at_byte, bytes())
        print('sent {} bytes'.format(sent))

    def handle_ack_upload(self, data, addr):
        print('received Ack_Upload from', addr)

        upload_id = int.from_bytes(data[:4], byteorder='big')
        acked_bytes = int.from_bytes(data[4:12], byteorder='big')
        print(upload_id, acked_bytes)

    # file sync methods
    def upload_file(self, filepath, filehash=None):
        if filehash is None:
            filehash = sha256.hash_file(filepath)
        print("upload", filepath, sha256.hex(filehash))

        statinfo = os.stat(self.path + filepath.decode('utf8'))

        # send file metadata
        sent = self.send_file_metadata(filehash, filepath, statinfo)
        print('sent {} bytes'.format(sent))

    def delete_file(self, filepath, hash=None):
        print("delete", filepath)

    def update_file(self, filepath, hash=None):
        if filehash is None:
            filehash = sha256.hash_file(filepath)
        print("update", filepath, sha256.hex(filehash))
        self.upload_file(filepath, filehash)

    def move_file(self, old_filepath, new_filepath, hash=None):
        # sha256.hash_file(new_filepath)
        print("move", old_filepath, "to", new_filepath)


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
