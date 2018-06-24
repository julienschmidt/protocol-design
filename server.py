"""
Server implementation
"""

import asyncio
import base64
import csv
import functools
import logging
import os
import signal

from lib import srp_auth
from lib.protocol import BaseScsyncProtocol, EncryptionMode, ErrorType


def get_users():
    users = list()
    with open('users.csv') as f:
        csvrd = csv.reader(f)
        for row in csvrd:
            username = row[0]
            salt = base64.standard_b64decode(row[1])
            vkey = base64.standard_b64decode(row[2])
            users.append((username, salt, vkey))
    return users


class ServerScsyncProtocol(BaseScsyncProtocol):
    """
    Server implementation of the scsync protocol
    """

    def __init__(self, loop, path, packets_per_second, users):
        super().__init__(loop, path, packets_per_second)
        print('Storing files in', path)

        # key for auth challenges
        # TODO: make persistent by writing to/reading from disk
        self.ckey = os.urandom(32)

        print('Users:')
        self.userinfo = dict()
        for user in users:
            username = user[0].encode('utf-8')
            salt = user[1]
            vkey = user[2]
            ukey = srp_auth.get_ukey(username, salt, self.ckey)
            self.userinfo[username] = (salt, vkey, ukey)
            print(" ", user[0])
        print()

    def handle_client_hello(self, data, addr):
        valid, request_id, username, client_seed = self.unpack_client_hello(
            data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        if username not in self.userinfo:
            logging.debug(
                "Client attempting login for unknown user '%s' in request %u", username, request_id)
            return

        salt, vkey, ukey = self.userinfo[username]

        logging.debug(
            "Client attempting login for existing user '%s' in request %u", username, request_id)

        server_seed, token = srp_auth.get_challenge(
            request_id, client_seed, username, salt, vkey, ukey)

        self.send_challenge(request_id, salt, server_seed, token, addr)

    def handle_challenge_response(self, data, addr):
        valid, request_id, proof, client_seed, enc_mode, username, token = self.unpack_challenge_response(
            data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        if len(token) != 60:
            return

        salt, vkey, ukey = self.userinfo[username]

        session_key = srp_auth.verify_challenge(
            request_id, proof, client_seed, token, username, salt, vkey, ukey)
        if not session_key:
            logging.debug(
                "Login attempt for user '%s' in request %u failed!", username, request_id)
            return

        logging.debug(
            "Login attempt for user '%s' in request %u successful.", username, request_id)

        encryptor = self.get_encryptor(enc_mode, session_key)
        if not encryptor:
            logging.debug(
                "Invalid encryption mode in request %u. Abort.", request_id)
            return

        # TODO: use server-assigned session ID instead
        session_id = request_id
        self.sessions[session_id] = {
            'encryptor': encryptor,
            'nonce': 1,
        }

        server_state = dict()
        for filename, fileinfo in self.fileinfo.items():
            server_state[filename] = fileinfo["filehash"]

        # respond with Current_Server_State
        self.send_current_server_state(session_id, server_state, addr)

    def handle_ack_error(self, session_id, data, addr):
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

    def handle_client_update_request(self, session_id, data, addr):
        valid, epoch = self.unpack_client_update_request(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        logging.debug(
            'Client requested update (epoch: %d)', epoch)

        # TODO: only sent filelist if changes since last epoch
        server_state = dict()
        for filename, fileinfo in self.fileinfo.items():
            server_state[filename] = fileinfo["filehash"]

        # respond with Current_Server_State
        self.send_current_server_state(session_id, server_state, addr)

    def handle_client_file_request(self, session_id, data, addr) -> None:
        valid, filehash, filename = self.unpack_client_file_request(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        logging.debug('Requested file named \"%s\" with hash: %s',
                      filename, filehash)

        if filename in self.fileinfo and filehash == self.fileinfo[filename]["filehash"]:
            logging.debug(
                "Send file metadata for file named named \"%s\" to %s", filename, addr)
            self.send_file_metadata(session_id, filename,
                                    self.fileinfo[filename], addr=addr)
        else:
            logging.error(
                'Requested file \"%s\" with hash: %s not present on server!', filename, filehash)
            self.communicate_error(
                filename, filehash, ErrorType.File_Not_Present, None, None, addr)

    def handle_file_delete(self, session_id, data, addr):
        valid, filehash, filename = self.unpack_file_delete(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        fileinfo = self.fileinfo.get(filename, None)
        if fileinfo is None or self.fileinfo[filename]["filehash"] != filehash:
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
        self.send_ack_delete(session_id, filehash, filename, addr)

    def handle_file_rename(self, session_id, data, addr):
        valid, filehash, old_filename, new_filename = self.unpack_file_rename(
            data)

        if not valid or self.fileinfo[old_filename]["filehash"] != filehash:
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
        fileinfo = self.fileinfo[old_filename]
        del self.fileinfo[old_filename]
        self.fileinfo[new_filename] = fileinfo

        print("Renamed/Moved file \"%s\" to \"%s\"" %
              (old_filename, new_filename))

        self.send_ack_rename(session_id, filehash,
                             old_filename, new_filename, addr)

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
    users = get_users()

    loop = asyncio.get_event_loop()

    # bind to UDP socket
    server_address = (args.host, args.port)
    print('Starting UDP server on {}:{}\n'.format(*server_address))
    listen = loop.create_datagram_endpoint(
        lambda: ServerScsyncProtocol(loop, args.path, args.cc, users),
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
