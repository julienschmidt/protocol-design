"""
Server implementation
"""

import asyncio
import functools
import logging
import os
import signal
import pyrsync2

from lib.protocol import BaseScsyncProtocol, ErrorType


class ServerScsyncProtocol(BaseScsyncProtocol):
    """
    Server implementation of the scsync protocol
    """

    def __init__(self, loop, path, packets_per_second):
        super().__init__(loop, path, packets_per_second)
        print('Storing files in', path)

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

        server_state = dict()
        for filename, fileinfo in self.fileinfo.items():
            server_state[filename] = fileinfo["filehash"]

        # respond with Current_Server_State
        self.send_current_server_state(server_state, addr)

    def handle_client_file_request(self, data, addr) -> None:
        valid, filehash, filename = self.unpack_client_file_request(data)
        if not valid:
            self.handle_invalid_packet(data, addr)
            return

        logging.debug('Requested file named \"%s\" with hash: %s', filename, filehash)

        if filename in self.fileinfo and filehash == self.fileinfo[filename]["filehash"]:
            logging.debug("Send file metadata for file named named \"%s\" to %s", filename, addr)
            self.send_file_metadata(filename, self.fileinfo[filename], addr=addr)
        else:
            logging.error('Requested file \"%s\" with hash: %s not present on server!', filename, filehash)
            self.communicate_error(filename, filehash, ErrorType.File_Not_Present, None, None, addr)

    def handle_file_delete(self, data, addr):
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
        self.send_ack_delete(filehash, filename, addr)

    def handle_file_rename(self, data, addr):
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

        self.send_ack_rename(filehash, old_filename, new_filename, addr)

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
        lambda: ServerScsyncProtocol(loop, args.path, args.packets_per_second),
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
