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

import aiofiles

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

        self.active_uploads = dict()
        self.pending_upload_acks = dict()

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

        # cancel all upload tasks
        for upload in self.active_uploads.values():
            upload[1].cancel()

        # stop the file observer
        if self.observer:
            self.observer.stop()

        # stop the event loop
        self.loop.stop()

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
        if fileinfo['filehash'] != filehash:
            # file changed in the meantime
            return

        upload_task = self.loop.create_task(self.do_upload(
            filename, fileinfo, upload_id, resume_at_byte))
        self.active_uploads[filename] = (upload_id, upload_task)

    def handle_ack_upload(self, data, addr):
        valid, upload_id, acked_bytes = self.unpack_ack_upload(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        ack = self.pending_upload_acks.get(upload_id, None)
        if ack is None:
            return
        ack.set_result(acked_bytes)

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

        logging.info("Deleted file %s", filename)

        fileinfo = self.fileinfo[filename]
        filehash = fileinfo["filehash"]
        self.send_file_delete(filehash, filename)
        # TODO Wait for Delete File Ack and if it doesn't arrive, resend.

    def handle_ack_delete(self, data, addr):
        valid, filehash, filename = self.unpack_ack_delete(data)

        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        # TODO Stop timer that should resend Delete File Ack if filename and
        # hash are the same as the timer's
        logging.info("Deleted file %s was acknowledged", filename)

    def update_file(self, filename, fileinfo=None):
        """
        Update the given file on the server by uploading the new content.
        """

        logging.info("Updated %s", filename)

        self.upload_file(filename, fileinfo)

    def move_file(self, old_filename, new_filename):
        """
        Move a file on the server by changing its path.
        """

        logging.info("Renamed/Moved file %s to %s", old_filename, new_filename)

        filehash = self.fileinfo[old_filename]["filehash"]
        self.send_file_rename(filehash, old_filename, new_filename)
        # TODO Wait for Rename File Ack and if it doesn't arrive, resend.

    def handle_ack_rename(self, data, addr):
        valid, filehash, old_filename, new_filename = self.unpack_ack_rename(
            data)

        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        # TODO Stop timer that should resend Rename File Ack if old_filename,
        # new_filename and hash are the same as the timer's
        logging.info("Renamed/Moved file %s to %s was acknowledged",
                     old_filename, new_filename)

    async def do_upload(self, filename, fileinfo, upload_id, resume_at_byte):
        filepath = self.path + filename.decode('utf8')
        size = fileinfo['size']
        try:
            async with aiofiles.open(filepath, mode='rb', loop=self.loop) as file:
                if resume_at_byte > 0:
                    await file.seek(resume_at_byte)

                pos = resume_at_byte
                while pos < size:
                    buf = await file.read(512)
                    ack = asyncio.Future(loop=self.loop)
                    self.pending_upload_acks[upload_id] = ack
                    self.send_file_upload(upload_id, pos, buf)
                    try:
                        acked_bytes = await asyncio.wait_for(ack, timeout=1.0, loop=self.loop)
                    except asyncio.TimeoutError:
                        print("ack timeout, resending...")
                        await file.seek(pos)
                        continue
                    pos = acked_bytes
        except (asyncio.CancelledError, RuntimeError):
            return


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
