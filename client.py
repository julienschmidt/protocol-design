"""
Client implementation
"""

import asyncio
import functools
import os
import random
import signal
import logging

import aiofiles

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from lib import files
from lib import sha256
from lib.buffer import ChunkSendBuffer
from lib.protocol import BaseScsyncProtocol, ErrorType


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


class ClientScsyncProtocol(BaseScsyncProtocol):
    """
    Client implementation of the scsync protocol
    """

    def __init__(self, loop, path):
        super().__init__(path)
        self.loop = loop

        # Set fetch update interval
        self.fetch_intercal = 2.5

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
        self.pending_hello_callback = None
        self.pending_metadata_callbacks = dict()
        self.pending_delete_callbacks = dict()
        self.pending_rename_callbacks = dict()

    # Socket State
    def connection_made(self, transport):
        super().connection_made(transport)

        # workaround to make update() execute after
        # loop.run_until_complete(connect) returned
        self.loop.call_later(0.001, self.update)

    def connection_lost(self, exc):
        print("Socket closed, stop the event loop")
        self.stop()

    # UNIX Signals
    def signal(self, signame) -> None:
        """
        UNIX signal handler.
        """
        print("Got signal %s: exit" % signame)
        self.stop()

    # State
    def update(self) -> None:
        """
        Start client protocol by sending a Client_Update_Request.
        """
        # schedule resend (canceled if Current_Server_State received)
        callback_handle = self.loop.call_later(self.resend_delay, self.update)
        self.pending_hello_callback = callback_handle

        self.send_client_update_request(self.client_id)

    def stop(self) -> None:
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

    def __cancel_resend(self, register, key) -> bool:
        if key is None:
            callback_handle = register
            if callback_handle is None:
                return False
            callback_handle.cancel()
            register = None
            return True
        else:
            callback_handle = register.get(key, None)
            if callback_handle is None:
                return False
            callback_handle.cancel()
            del register[key]
            return True

    def __cancel_upload(self, filename, filehash, cancel_metadata=True) -> None:
        if cancel_metadata:
            self.__cancel_resend(self.pending_metadata_callbacks, filename)
        fileinfo = self.fileinfo.get(filename, None)
        if fileinfo is not None and filehash == fileinfo['filehash']:
            active_upload = self.active_uploads.get(filename, None)
            if active_upload is not None:
                active_upload[1].cancel()

    # Local file handling
    def remove_local_file(self, filename) -> None:
        """
        Remove a local file from the file system
        """

        # Remove the file from the file system
        if os.path.isfile(self.path + filename.decode("utf-8")):
            os.remove(self.path + filename.decode("utf-8"))
        else:
            logging.warning("Could not remove file \"%s\"", filename)
            return

        # Remove the file from the internal fileinfo dict
        del self.fileinfo[filename]

        print("Deleted file \"%s\"" % filename)

    def rename_local_file(self, old_filename, new_filename) -> None:
        """
        Rename a local file
        """

        # Rename the file from the file system
        if os.path.isfile(self.path + old_filename.decode("utf-8")):
            os.renames(self.path + old_filename.decode("utf-8"),
                       self.path + new_filename.decode("utf-8"))
        else:
            logging.warning("Could not rename \"%s\" to \"%s\"", old_filename, new_filename)
            return

        # Remove the old reference from the internal fileinfo dict and add a
        # new one for the new_filename
        filehash = self.fileinfo[old_filename]
        del self.fileinfo[old_filename]
        self.fileinfo[new_filename] = filehash

        print("Renamed/Moved file \"%s\" to \"%s\"" %(old_filename, new_filename))

    # Packet Handlers
    def handle_error(self, data, addr) -> None:
        logging.info('received Error from %s', addr)
        valid, filehash, filename, error_type, error_id, description = self.unpack_error(
            data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return
        logging.error('%s [%s]: %s %s', filename, sha256.hex(filehash),
                      error_type, description)

        if error_type == ErrorType.File_Hash_Error:
            print('reuploading file \"%s\"' % filename.decode('utf8'))
            self.loop.call_soon(self.upload_file, filename)
        elif error_type in [ErrorType.Out_Of_Memory, ErrorType.Conflict, ErrorType.Upload_Failed]:
            self.__cancel_upload(filename, filehash)
        else:
            logging.error('unknown error')

        self.send_ack_error(error_id)

    def handle_current_server_state(self, data, addr) -> None:
        valid, remote_files = self.unpack_current_server_state(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        # cancel resend
        if not self.__cancel_resend(self.pending_hello_callback, None):
            return

        # build file dir diff
        for filename, fileinfo in self.fileinfo.items():
            if filename not in remote_files:
                new_file_name = None
                for remote_file_name in remote_files.keys():
                    if remote_files[remote_file_name] == fileinfo['filehash']:
                        new_file_name = remote_file_name

                if new_file_name != None:
                    # If the local file hash can be found in the remote files but the name is different, we assume a
                    # we assume it has been renamed by an other client --> Rename local copy
                    self.loop.call_soon(self.rename_local_file, filename, new_file_name)
                else:
                    # If local file is not in remote files and there is no suiting hash (possible rename)
                    # we assume it has been deleted by an other client --> Remove local copy
                    self.loop.call_soon(self.remove_local_file, filename)
            # elif fileinfo['filehash'] != remote_files[filename]:
                # If filehash is not equal we assume an other client has updated the file and we request the new file
                # self.loop.call_soon(self.request_file, fileinfo)

        # Call update() repeatedly to get an update of the files on the server and react accordingly
        self.loop.call_later(self.fetch_intercal, self.update)

    def handle_ack_metadata(self, data, addr) -> None:
        valid, filehash, filename, upload_id, resume_at_byte = self.unpack_ack_metadata(
            data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        # cancel resend
        if not self.__cancel_resend(self.pending_metadata_callbacks, filename):
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

    def handle_ack_upload(self, data, addr) -> None:
        valid, upload_id, acked_bytes = self.unpack_ack_upload(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        ack = self.pending_upload_acks.get(upload_id, None)
        if ack is None:
            return

        if acked_bytes > ack[1]:
            ack[1] = acked_bytes
            ack[0].set()  # notify about new ACK

    def handle_ack_delete(self, data, addr) -> None:
        valid, filehash, filename = self.unpack_ack_delete(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        fileinfo = self.fileinfo.get(filename, None)
        if fileinfo is None or fileinfo['filehash'] != filehash:
            self.handle_invalid_packet(data, addr)
            return

        # cancel resend
        if not self.__cancel_resend(self.pending_delete_callbacks, filename):
            return

        del self.fileinfo[filename]

        print("Deleted file \"%s\" was acknowledged" % filename)

    def handle_ack_rename(self, data, addr) -> None:
        valid, filehash, old_filename, new_filename = self.unpack_ack_rename(
            data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        fileinfo = self.fileinfo.get(old_filename, None)
        if fileinfo is None or fileinfo['filehash'] != filehash:
            self.handle_invalid_packet(data, addr)
            return

        del self.fileinfo[old_filename]
        self.fileinfo[new_filename] = fileinfo

        # cancel resend
        if not self.__cancel_resend(self.pending_rename_callbacks, old_filename):
            return

        print("Renamed/Moved file \"%s\" to \"%s\" was acknowledged" %
              (old_filename, new_filename))

    # file sync methods
    def upload_file(self, filename, fileinfo=None) -> None:
        """
        Upload the given file to server.
        """
        if fileinfo is None:
            fileinfo = self.get_fileinfo(filename.decode('utf8'))
            # prevent double uploads do to IO-notifications (e.g. create and
            # modify)
            existing_fileinfo = self.fileinfo.get(filename, None)
            if existing_fileinfo is not None and existing_fileinfo == fileinfo:
                return
        self.fileinfo[filename] = fileinfo
        print("Upload \"%s\"" % filename)

        # cancel any active upload for the same file
        active_upload = self.active_uploads.get(filename, None)
        if not active_upload is None:
            active_upload[1].cancel()

        # schedule resend (canceled if ack'ed)
        callback_handle = self.loop.call_later(
            self.resend_delay, self.upload_file, filename)
        self.pending_metadata_callbacks[filename] = callback_handle

        # send file metadata
        self.send_file_metadata(filename, fileinfo)

    def delete_file(self, filename) -> None:
        """
        Delete the given file from the server.
        """

        # Check if the file was not deleted by the client program itself.
        if not (filename in self.fileinfo.keys()):
            return

        print("Deleted file \"%s\"" % filename)

        filehash = self.fileinfo[filename]["filehash"]

        # schedule resend (canceled if ack'ed)
        callback_handle = self.loop.call_later(
            self.resend_delay, self.delete_file, filename)
        self.pending_delete_callbacks[filename] = callback_handle

        self.send_file_delete(filehash, filename)

    def update_file(self, filename, fileinfo=None) -> None:
        """
        Update the given file on the server by uploading the new content.
        """
        self.upload_file(filename, fileinfo)

    def request_file(self, filename, filehash) -> None:
        """
        Request a given file on the server.
        """

        logging.debug("Request file \"%s\" with hash: %s", filename, filehash)

        self.send_client_file_request(filename, filehash)

    def move_file(self, old_filename, new_filename) -> None:
        """
        Move a file on the server by changing its path.
        """

        # Check if the file was not renamed/moved by the client program itself.
        if not (old_filename in self.fileinfo.keys()):
            return

        print("Renamed/Moved file \"%s\" to \"%s\"" %
              (old_filename, new_filename))

        filehash = self.fileinfo[old_filename]["filehash"]

        # schedule resend (canceled if ack'ed)
        callback_handle = self.loop.call_later(
            self.resend_delay, self.move_file, old_filename, new_filename)
        self.pending_rename_callbacks[old_filename] = callback_handle

        self.send_file_rename(filehash, old_filename, new_filename)

    async def do_upload(self, filename, fileinfo, upload_id, resume_at_byte) -> None:
        """
        This coroutine reads chunks from the given file and sends it as
        File_Upload packets. It then waits for acknowledgment and resends
        the packet if the sent chunk is not acknowledged.
        """
        filepath = self.path + filename.decode('utf8')
        size = fileinfo['size']
        try:
            async with aiofiles.open(filepath, mode='rb', loop=self.loop) as f:
                buf_size = self.chunk_size

                pos = 0
                if 0 < resume_at_byte <= size:
                    await f.seek(pos)
                    pos = resume_at_byte

                ack = [asyncio.Event(loop=self.loop), pos]
                self.pending_upload_acks[upload_id] = ack
                acked_bytes = pos

                # buffer for sent but not yet acknowledged chunks
                chunk_buffer = ChunkSendBuffer()
                while acked_bytes < size:
                    # TODO: `ahead` should be global
                    while pos < size and chunk_buffer.length < self.max_send_ahead:
                        logging.debug('reading chunk from pos %u', pos)
                        # read chunk from file
                        buf = await f.read(buf_size)
                        if not buf:
                            return

                        # send chunk
                        self.send_file_upload(upload_id, pos, buf)

                        expiry_time = self.loop.time() + self.resend_delay
                        chunk_buffer.put(expiry_time, pos, buf)
                        pos += len(buf)

                        await asyncio.sleep(0.01)  # TODO: adjust to send rate

                        # check status
                        if ack[0].is_set():
                            ack[0].clear()
                            acked_bytes = ack[1]
                            logging.debug('got acks until %u', acked_bytes)
                            current_time = self.loop.time()
                            expired_chunks = chunk_buffer.adjust(
                                current_time, acked_bytes)
                            if expired_chunks:
                                self.__resend_chunks(
                                    expired_chunks, upload_id, chunk_buffer)

                    # wait blocking for ack
                    current_time = self.loop.time()
                    min_expiry_time = chunk_buffer.min_expiry_time()
                    if min_expiry_time is None:
                        continue
                    timeout = min_expiry_time - current_time
                    if timeout > 0:
                        try:
                            await asyncio.wait_for(ack[0].wait(),
                                                   timeout=timeout,
                                                   loop=self.loop)
                        except asyncio.TimeoutError:
                            pass
                    ack[0].clear()
                    acked_bytes = ack[1]
                    logging.debug('got acks until %u', acked_bytes)
                    expired_chunks = chunk_buffer.adjust(
                        current_time, acked_bytes)
                    if expired_chunks:
                        self.__resend_chunks(
                            expired_chunks, upload_id, chunk_buffer)

        except RuntimeError:
            return
        except IOError as e:
            description = os.strerror(e.errno)
            logging.error('IOError %u: %s', e.errno, description)
            del self.active_uploads[filename]
            self.loop.call_soon(self.upload_file, filename, fileinfo)
            return

        del self.active_uploads[filename]
        print("Upload of file \"%s\" was finished" % filename)

    def __resend_chunks(self, expired_chunks, upload_id, chunk_buffer):
        expiry_time = self.loop.time() + self.resend_delay
        for chunk in expired_chunks:
            logging.info("resending chunk starting at byte %u", chunk[1])
            self.send_file_upload(upload_id, chunk[1], chunk[2])
            chunk_buffer.put(expiry_time, chunk[1], chunk[2])


def run(args):
    """
    Start running as a client.
    """
    loop = asyncio.get_event_loop()

    # create UDP socket and start event loop listening to it
    server_address = (args.host, args.port)
    print('Trying to sync with {}:{}\n'.format(*server_address))
    connect = loop.create_datagram_endpoint(
        lambda: ClientScsyncProtocol(loop, args.path),
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
