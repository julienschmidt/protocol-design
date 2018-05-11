"""
Server implementation
"""

import asyncio
import functools
import os
import random
import signal
import time

from shutil import move
from tempfile import mkstemp

from lib import files
from lib import sha256
from lib.protocol import BaseCsyncProtocol, ErrorType


class FileUpload:
    """
    Data holder for file uploads.
    """

    def __init__(self, filehash, filename, size, permissions, modified_at):
        self.filehash = filehash
        self.filename = filename
        self.size = size
        self.permissions = permissions
        self.modified_at = modified_at

        # Buffered Chunks (Linked List)
        self.buffered_chunks = list()

        self.tmpfile = mkstemp()
        self.next_byte = 0


class ServerCsyncProtocol(BaseCsyncProtocol):
    """
    Server implementation of the csync protocol
    """

    def __init__(self, loop, path):
        super().__init__()
        self.loop = loop
        self.path = path

        print('storing in', path)

        self.fileinfo = dict()
        # list dir
        local_files = files.list(path)
        for file in local_files:
            filehash = sha256.hash_file(self.path + file)
            print(file, sha256.hex(filehash))
            self.fileinfo[file.encode('utf8')] = filehash
        print('\n')

        # maps upload IDs to in-progress file uploads
        self.uploads = dict()

        # maps filenames to assigned upload IDs, used to check for conflicts and
        # to resume uploads
        self.active_uploads = dict()

    def handle_client_hello(self, data, addr):
        print('received Client_Hello from', addr)
        valid, client_id = self.unpack_client_hello(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        print('client wants to connect with clientID:', client_id)

        # respond with Server_Hello
        sent = self.send_server_hello(self.fileinfo, addr)
        print('sent {} bytes back to {}'.format(sent, addr))

    def handle_file_metadata(self, data, addr):
        print('received File_Metadata from', addr)

        valid, filehash, filename, size, permissions, modified_at = self.unpack_file_metadata(
            data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return
        print(sha256.hex(filehash), filename, size,
              oct(permissions), time.ctime(modified_at))

        if filename in self.fileinfo and filehash == self.fileinfo[filename]:
            # just adjust metadata, no reupload necessary
            upload_id = 0
            start_at = size
            filepath = self.path + filename.decode('utf8')
            self.set_metadata(filepath, permissions, modified_at)

        else:
            upload_id, start_at, error = self.init_upload(
                filehash, filename, size, permissions, modified_at)
            if error:
                # TODO: send error
                pass

        sent = self.send_ack_metadata(
            filehash, filename, upload_id, start_at, addr)
        print('sent {} bytes back to {}'.format(sent, addr))

        print("upload size", size)
        if size == 0 and upload_id > 0:
            # no upload necessary
            self.finalize_upload(upload_id)

    def handle_file_upload(self, data, addr):
        print('received File_Upload from', addr)

        valid, upload_id, payload_start_byte, payload = self.unpack_file_upload(
            data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        print(upload_id, payload_start_byte, payload)

        sent = self.send_ack_upload(
            upload_id, payload_start_byte + len(payload), addr)
        print('sent {} bytes back to {}'.format(sent, addr))

    def gen_upload_id(self):
        """
        Generates a unique upload ID.
        """
        while True:
            upload_id = random.getrandbits(32)
            if upload_id not in self.uploads:
                return upload_id

    def init_upload(self, filehash, filename, size, permissions, modified_at):
        """
        Initialize a new file upload and return the assigned upload ID.
        """

        # check for existing upload to resume
        if filename in self.active_uploads:
            upload_id = self.active_uploads[filename]
            upload = self.uploads[upload_id]

            if upload.filehash == filehash and upload.size == size:
                # resume upload
                upload.permissions = permissions
                upload.modified_at = modified_at
                start_at = upload.next_byte
                return (upload_id, start_at, None)

            elif upload.modified_at >= modified_at:
                # only accept newer files
                return (0, 0, ErrorType.Conflict)

        start_at = 0
        upload_id = self.gen_upload_id()
        self.uploads[upload_id] = FileUpload(
            filehash, filename, size, permissions, modified_at)
        self.active_uploads[filename] = upload_id

        return (upload_id, start_at, None)

    def finalize_upload(self, upload_id):
        """
        Finalized file upload by moving the tmp file to the correct path and
        applying the file permissions and modified time.
        Afterwards it updates the servers fileinfo cache.
        """

        upload = self.uploads[upload_id]
        del self.uploads[upload_id]

        filepath = self.path + upload.filename.decode('utf8')
        move(upload.tmpfile[1], filepath)
        self.set_metadata(filepath, upload.permissions, upload.modified_at)

        # update cached fileinfo
        self.fileinfo[upload.filename] = upload.filehash
        print("finalized", upload.filename)

    def set_metadata(self, filepath, permissions, modified_at):
        """
        Set file metadata for the given file.
        """
        os.chmod(filepath, permissions)
        os.utime(filepath, times=(modified_at, modified_at))

    def signal(self, signame):
        """
        UNIX signal handler.
        """
        print("got signal %s: exit" % signame)
        self.loop.stop()

        # remove all temporary files
        for upload in self.uploads.values():
            os.remove(upload.tmpfile[1])


def run(args):
    """
    Start running as a Server.
    """
    loop = asyncio.get_event_loop()

    # bind to UDP socket
    print("Starting UDP server")
    server_address = (args.host, args.port)
    print('starting up on {}:{}\n'.format(*server_address))
    listen = loop.create_datagram_endpoint(
        lambda: ServerCsyncProtocol(loop, args.path),
        local_addr=server_address)
    transport, protocol = loop.run_until_complete(listen)

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
