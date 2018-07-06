"""
Client implementation
"""

import asyncio
import functools
import os
import random
import signal
import logging
import time

import srp

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from lib import files
from lib import sha256
from lib.protocol import BaseScsyncProtocol, EncryptionMode, ErrorType


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

        self.loop.call_soon_threadsafe(self.protocol.create_file,
                                       self.relative_filepath(event.src_path))

    def on_deleted(self, event):
        if event.is_directory:
            return

        if self.relative_filepath(event.src_path) in self.protocol.expected_delete_calls:
            self.protocol.remove_expected_delete_calls(
                self.relative_filepath(event.src_path))
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

    def __init__(self, loop, path, packets_per_second, username, password):
        print("Using user:", username)
        print()

        super().__init__(loop, path, packets_per_second)
        print("Syncing path:", self.path)
        print()

        # Set fetch update interval
        self.fetch_intercal = 10.0 # should be ~ 30s in production
        self.pending_update_callback = None

        # For time measurements
        self.times = None

        self.username = username
        self.authenticator = srp.User(
            username, password, hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        _, self.seed = self.authenticator.start_authentication()
        self.request_id = random.getrandbits(32)
        self.session_id = None

        # start file dir observer
        event_handler = FileEventHandler(self.loop, self.path, self)
        self.observer = Observer()
        self.observer.schedule(event_handler, self.path, recursive=False)
        self.observer.start()

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
    def signal(self, signame) -> None:
        """
        UNIX signal handler.
        """
        print("Got signal %s: exit" % signame)
        self.stop()

    # State
    def start(self) -> None:
        """
        Start client protocol by sending a Client_Hello.
        """
        # schedule resend (canceled if Server_Hello or Challenge is received)
        callback_handle = self.loop.call_later(self.resend_delay, self.start)
        self.pending_update_callback = callback_handle

        self.send_client_hello(self.request_id, self.username, self.seed)

    def update(self) -> None:
        """
        Update client by sending a Client_Update_Request.
        """
        # schedule resend (canceled if Current_Server_State received)
        callback_handle = self.loop.call_later(self.resend_delay, self.update)
        self.pending_update_callback = callback_handle

        self.send_client_update_request(self.session_id, self.epoch)

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

    def __cancel_upload(self, filename, filehash, cancel_metadata=True) -> None:
        if cancel_metadata:
            self.cancel_resend(self.pending_metadata_callbacks, filename)
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
            logging.warning("Could not rename \"%s\" to \"%s\"",
                            old_filename, new_filename)
            return

        # Remove the old reference from the internal fileinfo dict and add a
        # new one for the new_filename
        filehash = self.fileinfo[old_filename]
        del self.fileinfo[old_filename]
        self.fileinfo[new_filename] = filehash

        print("Renamed/Moved file \"%s\" to \"%s\"" %
              (old_filename, new_filename))

    # Packet Handlers
    def handle_error(self, session_id, data, addr) -> None:
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
            self.loop.call_soon(self.upload_file, filename, addr)
        elif error_type in [ErrorType.Out_Of_Memory, ErrorType.Conflict, ErrorType.Upload_Failed]:
            self.__cancel_upload(filename, filehash)
        else:
            logging.error('unknown error')

        self.send_ack_error(session_id, error_id)

    def handle_challenge(self, data, addr) -> None:
        valid, request_id, salt, server_seed, token = self.unpack_challenge(
            data)
        if not valid or request_id != self.request_id:
            self.handle_invalid_packet(data, addr)
            return

        proof = self.authenticator.process_challenge(salt, server_seed)
        if proof is None:
            return

        # cancel resend
        if not self.cancel_resend(self.pending_update_callback, None):
            return
        # schedule resend (canceled if Server_Hello or Challenge is received) to
        # start over if the handshake fails
        callback_handle = self.loop.call_later(self.resend_delay, self.start)
        self.pending_update_callback = callback_handle

        encryptor = self.get_encryptor(
            EncryptionMode.AES_256_GCM, self.authenticator.K)
        if not encryptor:
            logging.debug(
                "invalid encryption mode in request %u. Abort.", request_id)
            return

        # TODO: use server-assigned session ID instead
        self.session_id = request_id
        self.sessions[request_id] = {
            'encryptor': encryptor,
            'nonce': 0,
            'user': self.username
        }

        self.send_challenge_response(
            request_id, proof, self.seed, self.username.encode('utf-8'), token)

    def handle_current_server_state(self, session_id, data, addr) -> None:
        valid, epoch, remote_files = self.unpack_current_server_state(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        # cancel resend
        if not self.cancel_resend(self.pending_update_callback, None):
            return

        # nothing new
        if self.epoch == epoch:
            # Call update() repeatedly to get an update of the files on the server
            # and react accordingly
            self.loop.call_later(self.fetch_intercal, self.update)
            return
        self.epoch = epoch

        # build file dir diff
        for filename, fileinfo in self.fileinfo.items():
            if filename not in remote_files:
                new_file_name = None
                for remote_filename, remote_filehash in remote_files.items():
                    if remote_filehash == fileinfo['filehash']:
                        new_file_name = remote_filename

                if new_file_name is not None:
                    # If the local file hash can be found in the remote files but the name is different,
                    # we assume it has been renamed by an other client -->
                    # Rename local copy
                    self.rename_local_file(filename, new_file_name)
                else:
                    # If local file is not in remote files and there is no suiting hash (possible rename)
                    # we assume it has been deleted by an other client -->
                    # Remove local copy
                    self.remove_local_file(filename)

        for remote_filename, remote_filehash in remote_files.items():
            if remote_filename not in self.fileinfo.keys() or self.fileinfo[remote_filename]['filehash'] != remote_filehash:
                # If after renaming and removing files that might have changed on the server
                # we check of any of the remote files still is not present on the client or is
                # present but has a different hash and if so we assume that the file must be
                # requested from the server using a request_file packet
                self.loop.call_soon(self.request_file,
                                    remote_filename, remote_filehash, addr)

        # Call update() repeatedly to get an update of the files on the server
        # and react accordingly
        self.loop.call_later(self.fetch_intercal, self.update)

    def handle_ack_delete(self, session_id, data, addr) -> None:
        valid, filehash, filename = self.unpack_ack_delete(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        fileinfo = self.fileinfo.get(filename, None)
        if fileinfo is None or fileinfo['filehash'] != filehash:
            self.handle_invalid_packet(data, addr)
            return

        # cancel resend
        if not self.cancel_resend(self.pending_delete_callbacks, filename):
            return

        del self.fileinfo[filename]

        print("Deleted file \"%s\" was acknowledged" % filename)

    def handle_ack_rename(self, session_id, data, addr) -> None:
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
        if not self.cancel_resend(self.pending_rename_callbacks, old_filename):
            return

        print("Renamed/Moved file \"%s\" to \"%s\" was acknowledged" %
              (old_filename, new_filename))

    # file sync methods
    def create_file(self, filename) -> None:
        self.upload_file(self.session_id, filename)

    def delete_file(self, filename) -> None:
        """
        Delete the given file from the server.
        """

        # Check if the file was not deleted by the client program itself.
        if not filename in self.fileinfo.keys():
            return

        print("Deleted file \"%s\"" % filename)

        filehash = self.fileinfo[filename]["filehash"]

        # schedule resend (canceled if ack'ed)
        callback_handle = self.loop.call_later(
            self.resend_delay, self.delete_file, filename)
        self.pending_delete_callbacks[filename] = callback_handle

        self.send_file_delete(self.session_id, filehash, filename)

    def update_file(self, filename) -> None:
        """
        Update the given file on the server by uploading the new content.
        """

        self.fileinfo[filename] = self.get_fileinfo(filename.decode('utf8'))

        # schedule resend (canceled if ack'ed) TODO
        '''callback_handle = self.loop.call_later(
            self.resend_delay, self.update_file, filename)
        self.pending_delete_callbacks[filename] = callback_handle'''

        self.send_file_update_request(
            self.session_id, filename, self.fileinfo[filename])

    def request_file(self, filename, filehash, addr) -> None:
        """
        Request a given file on the server.
        """

        logging.debug("Request file \"%s\" with hash: %s", filename, filehash)

        self.send_client_file_request(
            self.session_id, filename, filehash, addr)

    def move_file(self, old_filename, new_filename) -> None:
        """
        Move a file on the server by changing its path.
        """

        # Check if the file was not renamed/moved by the client program itself.
        if not old_filename in self.fileinfo.keys():
            return

        print("Renamed/Moved file \"%s\" to \"%s\"" %
              (old_filename, new_filename))

        filehash = self.fileinfo[old_filename]["filehash"]

        # schedule resend (canceled if ack'ed)
        callback_handle = self.loop.call_later(
            self.resend_delay, self.move_file, old_filename, new_filename)
        self.pending_rename_callbacks[old_filename] = callback_handle

        self.send_file_rename(self.session_id, filehash,
                              old_filename, new_filename)


def run(args):
    """
    Start running as a client.
    """
    loop = asyncio.get_event_loop()

    # create UDP socket and start event loop listening to it
    server_address = (args.host, args.port)
    print('Trying to sync with {}:{}\n'.format(*server_address))
    connect = loop.create_datagram_endpoint(
        lambda: ClientScsyncProtocol(
            loop, args.path, args.cc, args.user, args.password),
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
