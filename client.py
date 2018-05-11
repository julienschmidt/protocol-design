"""
Client implementation
"""

import asyncio
import functools
import os
import random
import signal
import stat
import logging

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
        print("ClientID:", self.client_id)

        print("Syncing path:", self.path)

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
        size = statinfo[stat.ST_SIZE]
        permissions = (statinfo[stat.ST_MODE] & 0o777)
        modified_at = statinfo[stat.ST_MTIME]

        if logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.debug("Got file info of file %s. " +
                          "[filehash: %s, size: %u, permissions: %o, modified_at: %u]",
                          file, sha256.hex(filehash), size, permissions, modified_at)

        return {
            'filehash': filehash,
            'size': size,
            'permissions': permissions,
            'modified_at': modified_at,
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
        print("Got signal %s: exit" % signame)
        self.stop()

    # State
    def start(self):
        """
        Start client protocol by sending a Client_Hello.
        """

        self.send_client_hello(self.client_id)

    def stop(self):
        """
        Stop the client.
        """
        self.loop.stop()
        if self.observer:
            self.observer.stop()

    # Packet Handlers
    def handle_server_hello(self, data, addr):
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

    def handle_ack_metadata(self, data, addr):
        valid, filehash, filename, upload_id, resume_at_byte = self.unpack_ack_metadata(
            data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        fileinfo = self.fileinfo[filename]
        if fileinfo['size'] <= resume_at_byte:
            # no further upload necessary
            return

        self.send_file_upload(upload_id, resume_at_byte, bytes())

    def handle_ack_upload(self, data, addr):
        valid, upload_id, acked_bytes = self.unpack_ack_upload(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

    # file sync methods
    def upload_file(self, filename, fileinfo=None):
        """
        Upload the given file to server.
        """
        if fileinfo is None:
            fileinfo = self.get_fileinfo(filename.decode('utf8'))
        self.fileinfo[filename] = fileinfo

        # send file metadata
        self.send_file_metadata(filename, fileinfo)

    def delete_file(self, filename):
        """
        Delete the given file from the server.
        """

        logging.info("Delete %s", filename)

        # TODO: get cached filehash of deleted file and send File_Delete packet

    def update_file(self, filename, fileinfo=None):
        """
        Update the given file on the server by uploading the new content.
        """

        logging.info("Update %s", filename)

        self.upload_file(filename, fileinfo)

    def move_file(self, old_filename, new_filename):
        """
        Move a file on the server by changing its path.
        """

        logging.info("Move file %s to %s", old_filename, new_filename)


def run(args):
    """
    Start running as a client.
    """
    loop = asyncio.get_event_loop()

    # create UDP socket and start event loop listening to it
    server_address = (args.host, args.port)
    print('Trying to sync with {}:{}\n'.format(*server_address))
    connect = loop.create_datagram_endpoint(
        lambda: ClientCsyncProtocol(loop, args.path),
        remote_addr=server_address)
    transport, protocol = loop.run_until_complete(connect)

    for signame in ('SIGINT', 'SIGTERM'):
        loop.add_signal_handler(getattr(signal, signame),
                                functools.partial(protocol.signal, signame))

    print("Event loop running forever, press Ctrl+C to interrupt.")
    print("PID %s: send SIGINT or SIGTERM to exit.\n\n" % os.getpid())

    try:
        loop.run_forever()
    finally:
        transport.close()
        loop.close()
