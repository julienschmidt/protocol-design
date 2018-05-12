"""
Server implementation
"""

import asyncio
import functools
import os
import random
import signal
import logging

import aiofiles

from shutil import move
from tempfile import mkstemp

from lib import files
from lib import sha256
from lib.protocol import BaseCsyncProtocol, ErrorType


class ServerCsyncProtocol(BaseCsyncProtocol):
    """
    Server implementation of the csync protocol
    """

    def __init__(self, loop, path):
        super().__init__()
        self.loop = loop
        self.path = path

        print('Storing files in', path)

        self.fileinfo = dict()
        # list dir
        local_files = files.list(path)
        for file in local_files:
            filehash = sha256.hash_file(self.path + file)
            self.fileinfo[file.encode('utf8')] = filehash

            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.debug("Found file at %s with hash %s",
                              file, sha256.hex(filehash))

        # maps upload IDs to in-progress file uploads
        self.uploads = dict()

        # maps filenames to assigned upload IDs, used to check for conflicts and
        # to resume uploads
        self.active_uploads = dict()

    def handle_client_hello(self, data, addr):
        valid, client_id = self.unpack_client_hello(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        print('Client wants to connect with clientID:', client_id)

        # respond with Server_Hello
        self.send_server_hello(self.fileinfo, addr)

    def handle_file_metadata(self, data, addr):
        valid, filehash, filename, size, permissions, modified_at = self.unpack_file_metadata(
            data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

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

        self.send_ack_metadata(filehash, filename, upload_id, start_at, addr)

    def handle_file_upload(self, data, addr):
        valid, upload_id, start_byte, payload = self.unpack_file_upload(
            data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        upload = self.uploads.get(upload_id, None)
        if upload is None:
            return
        next_chunk = upload['next_chunk']
        if next_chunk.done():
            return
        next_chunk.set_result((start_byte, payload, addr))


    def handle_file_delete(self, data, addr):
        valid, filehash, filename = self.unpack_file_delete(data)

        if not valid or self.fileinfo[filename] != filehash:
            self.handle_invalid_packet(data, addr)
            return

        # Remove the file from the file system
        if os.path.isfile(self.path + filename):
            os.remove(self.path + filename)
        else:
            self.handle_invalid_packet(data, addr)
            return

        # Remove the file from the internal fileinfo dict
        del self.fileinfo[filename]

        # Send Ack-Packet
        self.send_ack_delete(filehash, filename)

    def handle_file_rename(self, data, addr):
        valid, filehash, old_filename, new_filename = self.unpack_file_rename(data)

        if not valid or self.fileinfo[old_filename] != filehash:
            self.handle_invalid_packet(data, addr)
            return

        # Rename the file from the file system
        if os.path.isfile(self.path + old_filename):
            os.renames(self.path + old_filename, self.path + new_filename)
        else:
            self.handle_invalid_packet(data, addr)
            return

        # Remove the old reference from the internal fileinfo dict and add a
        # new one for the new_filename
        del self.fileinfo[old_filename]
        self.fileinfo[new_filename] = filehash

        self.send_ack_rename(filehash, old_filename, new_filename)

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

        print("receiving new file upload of file {} with size {}".format(filename, size))

        # check for existing upload to resume
        if filename in self.active_uploads:
            upload_id, _ = self.active_uploads[filename]
            upload = self.uploads[upload_id]

            if upload['filehash'] == filehash and upload['size'] == size:
                # resume upload
                upload['permissions'] = permissions
                upload['modified_at'] = modified_at
                start_at = upload['next_byte']
                return (upload_id, start_at, None)

            elif upload['modified_at'] >= modified_at:
                # only accept newer files
                return (0, 0, ErrorType.Conflict)

        start_at = 0
        upload_id = self.gen_upload_id()
        upload = {
            'filehash': filehash,
            'filename': filename,
            'size': size,
            'permissions': permissions,
            'modified_at': modified_at,

            'tmpfile': mkstemp(),
            'next_byte': 0,

            # Future to pass chunks to the receiver coroutine
            'next_chunk': asyncio.Future(loop=self.loop),
        }

        if size == 0:
            # no upload necessary
            self.finalize_upload(upload_id, upload)
        else:
            upload_task = self.loop.create_task(self.receive_upload(upload_id, upload))
            self.uploads[upload_id] = upload
            self.active_uploads[filename] = (upload_id, upload_task)

        return (upload_id, start_at, None)

    async def receive_upload(self, upload_id, upload):
        size = upload['size']
        try:
            async with aiofiles.open(upload['tmpfile'][1], mode='wb', loop=self.loop) as file:
                pos = 0
                while pos < size:
                    # TODO: add timeout
                    start_byte, payload, addr = await upload['next_chunk']
                    upload['next_chunk'] = asyncio.Future(loop=self.loop)
                    print('chunk', pos, start_byte, len(payload))
                    if start_byte != pos:
                        # TODO: buffer chunks instead
                        if start_byte > pos:
                            continue
                        diff = pos-start_byte
                        if diff > len(payload):
                            continue
                        payload = payload[diff:]
                    pos += len(payload)
                    self.send_ack_upload(upload_id, pos, addr)
                    await file.write(payload)
        except RuntimeError:
            return
        self.finalize_upload(upload_id, upload)

    def finalize_upload(self, upload_id, upload=None):
        """
        Finalized file upload by moving the tmp file to the correct path and
        applying the file permissions and modified time.
        Afterwards it updates the servers fileinfo cache.
        """
        if upload is None:
            upload = self.uploads[upload_id]

        filename = upload['filename']
        filehash = upload['filehash']

        del self.uploads[upload_id]
        del self.active_uploads[filename]

        filepath = self.path + filename.decode('utf8')
        move(upload['tmpfile'][1], filepath)
        self.set_metadata(filepath, upload['permissions'], upload['modified_at'])

        # update cached fileinfo
        # TODO: check filehash
        self.fileinfo[filename] = filehash

        print("finalized upload of file %s", filename)

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
        print("Got signal %s: exit" % signame)
        self.loop.stop()

        # remove all temporary files
        for upload in self.uploads.values():
            os.remove(upload['tmpfile'][1])


def run(args):
    """
    Start running as a Server.
    """
    loop = asyncio.get_event_loop()

    # bind to UDP socket
    server_address = (args.host, args.port)
    print('Starting UDP server on {}:{}\n'.format(*server_address))
    listen = loop.create_datagram_endpoint(
        lambda: ServerCsyncProtocol(loop, args.path),
        local_addr=server_address)
    transport, protocol = loop.run_until_complete(listen)

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
