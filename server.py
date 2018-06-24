"""
Server implementation
"""

import asyncio
import errno
import functools
import hashlib
import logging
import os
import random
import signal
import pyrsync2

from shutil import move
from tempfile import mkstemp

import aiofiles

from lib import files
from lib import sha256
from lib.buffer import ChunkRecvBuffer
from lib.protocol import BaseScsyncProtocol, ErrorType


class ServerScsyncProtocol(BaseScsyncProtocol):
    """
    Server implementation of the scsync protocol
    """

    def __init__(self, loop, path):
        super().__init__(path)
        self.loop = loop
        self.max_buf_ahead = 4

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

        self.pending_error_callbacks = dict()

    def __error(self, filename, filehash, error_type, description=None, error_id=None, addr=None):
        if error_id is None:
            while True:
                error_id = random.getrandbits(32)
                if error_id not in self.pending_error_callbacks:
                    break

        # schedule resend (canceled if ack'ed)
        callback_handle = self.loop.call_later(
            self.resend_delay, self.__error,
            filename, filehash, error_type, description, error_id, addr)
        self.pending_error_callbacks[error_id] = callback_handle

        logging.info('%s [%s]: %s %s', filename, sha256.hex(filehash),
                     error_type, description)
        self.send_error(filename, filehash, error_type,
                        error_id, description, addr)

    def handle_ack_error(self, data, addr):
        valid, error_id = self.unpack_ack_error(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        # cancel resend
        callback_handle = self.pending_error_callbacks.get(error_id, None)
        if callback_handle is None:
            return
        callback_handle.cancel()
        del self.pending_error_callbacks[error_id]
        return

    def handle_client_update_request(self, data, addr):
        valid, client_id = self.unpack_client_update_request(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        logging.debug('Client with clientID \"%s\" requested update', client_id)

        # respond with Current_Server_State
        self.send_current_server_state(self.fileinfo, addr)

    def handle_client_file_request(self, data, addr) -> None:
        valid, filehash, filename = self.unpack_client_file_request(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        logging.debug('Requested file named \"%s\" with hash: %s', filename, filehash)

        if filename in self.fileinfo and filehash == self.fileinfo[filename]:
            fileinfo = self.get_fileinfo(filename.decode('utf8'))
            logging.debug("Send file metadata for file named named \"%s\" to %s", filename, addr)
            self.send_file_metadata(filename, fileinfo, addr=addr)
        else:
            logging.error('Requested file \"%s\" with hash: %s not present on server!', filename, filehash)
            self.__error(filename, filehash, ErrorType.File_Not_Present, None, None, addr)

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
            self.__set_metadata(filepath, permissions, modified_at)

        else:
            upload_id, start_at, error = self.__init_upload(
                filehash, filename, size, permissions, modified_at)
            if error:
                self.__error(filename, filehash, error, None, None, addr)
                return

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
        chunk_queue = upload['chunk_queue']
        chunk_queue.put_nowait((start_byte, payload, addr))

    def handle_file_update(self, data, addr):
        valid, update_id, start_byte, payload = self.unpack_file_update(
            data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        upload = self.uploads.get(update_id, None)
        if upload is None:
            return
        chunk_queue = upload['chunk_queue']
        chunk_queue.put_nowait((start_byte, payload, addr))

    def handle_file_delete(self, data, addr):
        valid, filehash, filename = self.unpack_file_delete(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        fileinfo = self.fileinfo.get(filename, None)
        if fileinfo is None or self.fileinfo[filename] != filehash:
            self.handle_invalid_packet(data, addr)
            return

        # Remove the file from the file system
        if os.path.isfile(self.path + filename.decode("utf-8")):
            os.remove(self.path + filename.decode("utf-8"))
        else:
            self.handle_invalid_packet(data, addr)
            return

        # Remove the file from the internal fileinfo dict
        del self.fileinfo[filename]

        print("Deleted file \"%s\"" % filename)

        # Send Ack-Packet
        self.send_ack_delete(filehash, filename, addr)

    def handle_file_rename(self, data, addr):
        valid, filehash, old_filename, new_filename = self.unpack_file_rename(
            data)

        if not valid or self.fileinfo[old_filename] != filehash:
            self.handle_invalid_packet(data, addr)
            return

        # Rename the file from the file system
        if os.path.isfile(self.path + old_filename.decode("utf-8")):
            os.renames(self.path + old_filename.decode("utf-8"),
                       self.path + new_filename.decode("utf-8"))
        else:
            self.handle_invalid_packet(data, addr)
            return

        # Remove the old reference from the internal fileinfo dict and add a
        # new one for the new_filename
        del self.fileinfo[old_filename]
        self.fileinfo[new_filename] = filehash

        print("Renamed/Moved file \"%s\" to \"%s\"" %
              (old_filename, new_filename))

        self.send_ack_rename(filehash, old_filename, new_filename, addr)

    def handle_file_update_request(self, data, addr):
        valid, filehash, filename, filesize, permissions, modified_at = self.unpack_file_update_request(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return
        # create new update entry and determine update_id
        upload_id, start_at, error = self.__init_update(
                filehash, filename, filesize, permissions, modified_at)
        if error:
            self.__error(filename, filehash, error, None, None, addr)
            return

        # create checksums
        file = open(self.path + filename.decode("utf-8"), "rb")
        hashes = list(pyrsync2.blockchecksums(file, 16384))
        file.close()

        #print(list(hashes))
        print("Update request received \"%s\"" % filename)
        self.send_file_update_response(filename, upload_id, start_at, hashes, addr)

    def __gen_upload_id(self):
        """
        Generates a unique upload ID.
        """
        while True:
            upload_id = random.getrandbits(32)
            if upload_id not in self.uploads:
                return upload_id

    def __init_upload(self, filehash, filename, size, permissions, modified_at):
        """
        Initialize a new file upload and return the assigned upload ID.
        """

        print("Receiving new file upload of file \"%s\" with size of %s bytes" % (
            filename, size))

        # check for existing upload to resume
        if filename in self.active_uploads:
            upload_id, _ = self.active_uploads[filename]
            upload = self.uploads[upload_id]

            if upload['filehash'] == filehash and upload['size'] == size:
                # resume upload
                upload['permissions'] = permissions
                upload['modified_at'] = modified_at
                start_at = upload['next_byte']
                logging.info("resume upload at byte %u", start_at)
                return (upload_id, start_at, None)

            elif upload['modified_at'] >= modified_at:
                # only accept newer files
                return (0, 0, ErrorType.Conflict)

        start_at = 0
        upload_id = self.__gen_upload_id()
        upload = {
            'filehash': filehash,
            'filename': filename,
            'size': size,
            'permissions': permissions,
            'modified_at': modified_at,

            'tmpfile': mkstemp(),
            'next_byte': 0,

            # Queue to pass chunks to the receiver coroutine
            'chunk_queue': asyncio.Queue(loop=self.loop),
        }

        upload_task = self.loop.create_task(
            self.__receive_upload(upload_id, upload))
        self.uploads[upload_id] = upload
        self.active_uploads[filename] = (upload_id, upload_task)

        return (upload_id, start_at, None)

    def __init_update(self, filehash, filename, size, permissions, modified_at):
        """
        Initialize a new file upload and return the assigned upload ID.
        """

        print("Receiving new file update of file \"%s\" with size of %s bytes" % (
            filename, size))

        # check for existing upload to resume
        if filename in self.active_uploads:
            update_id, _ = self.active_uploads[filename]
            upload = self.uploads[update_id]

            if upload['filehash'] == filehash and upload['size'] == size:
                # resume upload
                upload['permissions'] = permissions
                upload['modified_at'] = modified_at
                start_at = upload['next_byte']
                logging.info("resume update at byte %u", start_at)
                return (update_id, start_at, None)

            elif upload['modified_at'] >= modified_at:
                # only accept newer files
                return (0, 0, ErrorType.Conflict)

        start_at = 0
        update_id = self.__gen_upload_id()
        upload = {
            'filehash': filehash,
            'filename': filename,
            'size': size,
            'permissions': permissions,
            'modified_at': modified_at,

            'tmpfile': mkstemp(),
            'next_byte': 0,

            # Queue to pass chunks to the receiver coroutine
            'chunk_queue': asyncio.Queue(loop=self.loop),
        }

        upload_task = self.loop.create_task(
            self.__receive_update(update_id, upload))
        self.uploads[update_id] = upload
        self.active_uploads[filename] = (update_id, upload_task)

        return (update_id, start_at, None)

    async def __receive_upload(self, upload_id, upload):
        """
        This coroutine waits for incoming file chunks and writes them to the
        temporary file. When the whole file has been received, the filehash
        is verified before moving the file to the final destination and updating
        the cached fileinfo.
        """
        size = upload['size']
        tmpfile = upload['tmpfile'][1]
        m = hashlib.sha256()
        error = None
        if size > 0:
            try:
                async with aiofiles.open(tmpfile, mode='wb', loop=self.loop) as f:
                    chunk_queue = upload['chunk_queue']
                    buffered_chunks = ChunkRecvBuffer(self.max_buf_ahead)
                    pos = 0
                    while pos < size:
                        # TODO: add timeout
                        start_byte, payload, addr = await chunk_queue.get()
                        logging.debug("chunk %s, %s, %s", pos,
                                      start_byte, len(payload))
                        if start_byte != pos:
                            if start_byte > pos:
                                # ignore chunks with invalid start byte
                                if start_byte > size:
                                    continue

                                # buffer chunks which can not be immediately
                                # written
                                buffered_chunks.put(start_byte, payload)
                                continue

                            # skip old data
                            diff = pos - start_byte
                            if diff > len(payload):
                                continue
                            payload = payload[diff:]

                        pos += len(payload)

                        # get max available consecutive byte when including
                        # buffered chunks
                        available, matching_chunks = buffered_chunks.max_available(
                            pos)
                        upload['next_byte'] = available

                        # send ack with max available byte
                        self.send_ack_upload(upload_id, available, addr)

                        # update hash and write to file
                        m.update(payload)
                        await f.write(payload)

                        # handle buffered chunks that can be written now
                        while matching_chunks > 0:
                            start_byte, payload = buffered_chunks.pop()

                            # skip old data
                            diff = pos - start_byte
                            if diff > len(payload):
                                continue
                            payload = payload[diff:]

                            pos += len(payload)
                            m.update(payload)
                            await f.write(payload)
                            matching_chunks -= 1
            except (asyncio.CancelledError, RuntimeError):
                return
            except IOError as e:
                description = os.strerror(e.errno)
                logging.error('IOError %u: %s', e.errno, description)
                if e.errno in [errno.ENOSPC, errno.ENOMEM, errno.EFBIG]:
                    error = (ErrorType.Out_Of_Memory, description)
                else:
                    error = (ErrorType.Upload_Failed, description)

        filehash = m.digest()
        filename = upload['filename']

        del self.uploads[upload_id]
        del self.active_uploads[filename]

        if filehash != upload['filehash'] and error is None:
            logging.error('filehash of file \"%s\" did not match!', filename)
            error = (ErrorType.File_Hash_Error, "filehash does not match")

        if error is not None:
            os.remove(tmpfile)
            self.__error(filename, filehash, error[0], bytes(error[1]), None, addr)
            return

        # update cached fileinfo
        self.fileinfo[filename] = filehash

        filepath = self.path + filename.decode('utf8')
        move(tmpfile, filepath)
        self.__set_metadata(
            filepath, upload['permissions'], upload['modified_at'])

        print("finished upload of file \"%s\"" % filename)

    async def __receive_update(self, upload_id, upload):
        """
        This coroutine waits for incoming update chunks and stores them in a byte array. 
        When the whole update delta information has been received, the filehash
        is verified before updating the file to the final destination and updating
        the cached fileinfo.
        """
        size = upload['size']
        tmpfile = upload['tmpfile'][1]
        error = None
        data = b''
        if size > 0:
            try:
            
                chunk_queue = upload['chunk_queue']
                buffered_chunks = ChunkRecvBuffer(self.max_buf_ahead)
                pos = 0
                while pos < size:

                    # TODO: add timeout
                    start_byte, payload, addr = await chunk_queue.get()
                    # if startbyte 0: update size
                    if start_byte == 0:
                        size = int.from_bytes(payload[0:8], byteorder='big')

                    logging.debug("chunk %s, %s, %s", pos,
                                  start_byte, len(payload))
                    if start_byte != pos:
                        if start_byte > pos:
                            # ignore chunks with invalid start byte
                            if start_byte > size:
                                continue

                            # buffer chunks which can not be immediately
                            # written
                            buffered_chunks.put(start_byte, payload)
                            continue

                        # skip old data
                        diff = pos - start_byte
                        if diff > len(payload):
                            continue
                        payload = payload[diff:]

                    pos += len(payload)

                    # get max available consecutive byte when including
                    # buffered chunks
                    available, matching_chunks = buffered_chunks.max_available(pos)
                    upload['next_byte'] = available
                    # send ack with max available byte
                    self.send_ack_update(upload_id, available, addr)
                    # add data
                    data += payload
                    # handle buffered chunks that can be written now
                    while matching_chunks > 0:
                        start_byte, payload = buffered_chunks.pop()

                        # skip old data
                        diff = pos - start_byte
                        if diff > len(payload):
                            continue
                        payload = payload[diff:]

                        pos += len(payload)
                        data += payload
                        matching_chunks -= 1
            except (asyncio.CancelledError, RuntimeError):
                return
            except IOError as e:
                description = os.strerror(e.errno)
                logging.error('IOError %u: %s', e.errno, description)
                if e.errno in [errno.ENOSPC, errno.ENOMEM, errno.EFBIG]:
                    error = (ErrorType.Out_Of_Memory, description)
                else:
                    error = (ErrorType.Upload_Failed, description)

        filename = upload['filename']

        del self.uploads[upload_id]
        del self.active_uploads[filename]

        if error is not None:
            os.remove(tmpfile)
            self.__error(filename, filehash, error[0], bytes(error[1]), None, addr)
            return
        
        # Process received data
        # remove first 8 bytes: delta size
        data = data[8:]
        # remove 32 bytes: hash
        upload_hash = data[:32]
        data = data[32:]

        # check 
        if sha256.hash(data) != upload_hash and error is None:
            logging.error('deltahash for file \"%s\" did not match!', filename)
            error = (ErrorType.File_Hash_Error, "deltahash does not match")

        # generate delta list structure
        i = 0
        index_cnt = 0
        delta_list = []
        last_filled = False
        while i < len(data):
            checksum_length = int.from_bytes(data[i:i+4], byteorder='big')
            if checksum_length == 0:
                # special case when i == 0, index used is 0, otherwise a non int has been before, therefore index++
                if i == 0:
                    delta_list.append(0)
                else:
                    index_cnt += 1
                    delta_list.append(index_cnt)
                i = i + 4
                last_filled = False
            else:
                if not last_filled and i != 0:
                    index_cnt += 1
                    last_filled = True
                else:
                    # only for the i == 0 case important
                    last_filled = True
                # contains data, add the data
                delta_list.append(data[i+4:i+4+checksum_length])
                i = i + 4 + checksum_length

        # update
        file = open(self.path + filename.decode("utf-8"), "rb") 
        file.seek(0) 
        save_to = open(tmpfile, "wb") 
        pyrsync2.patchstream(file, save_to, delta_list, 16384)
        file.close()
        save_to.close()

        # check updated file size/hash
        filehash = sha256.hash_file(tmpfile)
        statinfo = os.stat(tmpfile)
        size = statinfo.st_size 

        if filehash != upload['filehash'] and error is None:
            logging.error('updated filehash for file \"%s\" did not match!', filename)
            error = (ErrorType.File_Hash_Error, "updated hash does not match")
        
        if size != upload['size'] and error is None:
            logging.error('updated size for file \"%s\" did not match!', filename)
            #TODO new error type for size missmatch (?)
            error = (ErrorType.File_Hash_Error, "updated size does not match")

        filepath = self.path + filename.decode('utf8')
        move(tmpfile, filepath)
        self.__set_metadata(filepath, upload['permissions'], upload['modified_at'])

        # update cached fileinfo
        self.fileinfo[filename] = filehash

        print("finished update of file \"%s\"" % filename)

    def __set_metadata(self, filepath, permissions, modified_at):
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
        lambda: ServerScsyncProtocol(loop, args.path),
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
