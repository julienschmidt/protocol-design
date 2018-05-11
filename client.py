"""
Client implementation
"""

import asyncio
import functools
import os
import random
import signal
import stat

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from lib import files
from lib import sha256
from lib.protocol import BaseCsyncProtocol


class FileEventHandler(FileSystemEventHandler):
    """
    File Event Handler
    """

    def __init__(self, loop, path, protocol):
        self.loop = loop
        self.path = path
        self.protocol = protocol

    def relative_filepath(self, file):
        """
        Return a filepath relative to the file dir for the given file.
        """
        return files.relative_filepath(file, self.path)

    def on_created(self, event):
        if event.is_directory:
            return

        self.loop.call_soon_threadsafe(self.protocol.upload_file,
                                       self.relative_filepath(event.src_path))

    def on_deleted(self, event):
        if event.is_directory:
            return

        self.loop.call_soon_threadsafe(self.protocol.delete_file,
                                       self.relative_filepath(event.src_path))

    def on_modified(self, event):
        if event.is_directory:
            return

        self.loop.call_soon_threadsafe(self.protocol.update_file,
                                       self.relative_filepath(event.src_path))

    def on_moved(self, event):
        if event.is_directory:
            return

        self.loop.call_soon_threadsafe(self.protocol.move_file,
                                       self.relative_filepath(event.src_path),
                                       self.relative_filepath(event.dest_path))


class ClientCsyncProtocol(BaseCsyncProtocol):
    """
    Client implementation of the csync protocol
    """

    def __init__(self, loop, path):
        super().__init__()
        self.loop = loop
        self.path = path

        # generate client ID
        self.client_id = random.getrandbits(64)
        print("clientID:", self.client_id)

        print('syncing path', self.path)

        self.fileinfo = dict()
        # list dir
        local_files = files.list(path)
        for file in local_files:
            filename = file.encode('utf8')
            self.fileinfo[filename] = self.get_fileinfo(file)

        # start file dir observer
        event_handler = FileEventHandler(self.loop, self.path, self)
        self.observer = Observer()
        self.observer.schedule(event_handler, self.path, recursive=False)
        self.observer.start()

    def get_fileinfo(self, file):
        """
        Get meta information about the given file.
        """
        filepath = self.path + file
        statinfo = os.stat(filepath)
        filehash = sha256.hash_file(filepath)
        print(file, sha256.hex(filehash))
        return {
            'filehash': filehash,
            'size': statinfo[stat.ST_SIZE],
            'permissions': (statinfo[stat.ST_MODE] & 0o777),
            'modified_at': statinfo[stat.ST_MTIME],
        }

    # Socket State
    def connection_made(self, transport):
        super().connection_made(transport)

        # workaround to make start() execute after
        # loop.run_until_complete(connect) returned
        self.loop.call_later(0.001, self.start)

    def connection_lost(self, exc):
        print("Socket closed, stop the event loop")
        self.stop()

    # UNIX Signals
    def signal(self, signame):
        """
        UNIX signal handler.
        """
        print("got signal %s: exit" % signame)
        self.stop()

    # State
    def start(self):
        """
        Start client protocol by sending a Client_Hello.
        """
        print("sending Client Hello...")
        sent = self.send_client_hello(self.client_id)
        print('sent {} bytes'.format(sent))

        print("awaiting Server Hello...\n")

    def stop(self):
        """
        Stop the client.
        """
        self.loop.stop()
        if self.observer:
            self.observer.stop()

    # Packet Handlers
    def handle_server_hello(self, data, addr):
        print("received Server Hello:")
        valid, remote_files = self.unpack_server_hello(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        # build file dir diff
        for filename, fileinfo in self.fileinfo.items():
            if filename not in remote_files:
                self.loop.call_soon(self.upload_file, filename, fileinfo)
            elif fileinfo['filehash'] != remote_files[filename]:
                self.loop.call_soon(self.update_file, filename, fileinfo)
        print('\n')

    def handle_ack_metadata(self, data, addr):
        print('received Ack_Metadata from', addr)

        valid, filehash, filename, upload_id, resume_at_byte = self.unpack_ack_metadata(
            data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return
        print(sha256.hex(filehash), filename, upload_id, resume_at_byte)

        sent = self.send_file_upload(upload_id, resume_at_byte, bytes())
        print('sent {} bytes'.format(sent))

    def handle_ack_upload(self, data, addr):
        print('received Ack_Upload from', addr)

        valid, upload_id, acked_bytes = self.unpack_ack_upload(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return
        print(upload_id, acked_bytes)

    # file sync methods
    def upload_file(self, filename, fileinfo=None):
        """
        Upload the given file to server.
        """
        if fileinfo is None:
            fileinfo = self.get_fileinfo(filename.decode('utf8'))
        self.fileinfo[filename] = fileinfo
        print("upload", filename, sha256.hex(fileinfo['filehash']))

        # send file metadata
        sent = self.send_file_metadata(filename, fileinfo)
        print('sent {} bytes'.format(sent))

    def delete_file(self, filename):
        """
        Delete the given file from the server.
        """
        print("delete", filename)
        # TODO: get cached filehash of deleted file and send File_Delete packet

    def update_file(self, filename, fileinfo=None):
        """
        Update the given file on the server by uploading the new content.
        """
        print("update", filename)
        self.upload_file(filename, fileinfo)

    def move_file(self, old_filename, new_filename):
        """
        Move a file on the server by changing its path.
        """
        # sha256.hash_file(new_filepath)
        print("move", old_filename, "to", new_filename)
        # TODO: specify file move / rename packet


def run(args):
    """
    Start running as a client.
    """
    loop = asyncio.get_event_loop()

    # create UDP socket and start event loop listening to it
    server_address = (args.host, args.port)
    print(server_address)
    connect = loop.create_datagram_endpoint(
        lambda: ClientCsyncProtocol(loop, args.path),
        remote_addr=server_address)
    transport, protocol = loop.run_until_complete(connect)

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
