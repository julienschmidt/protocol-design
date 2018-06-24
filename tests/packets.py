# pylint: disable=missing-docstring
import unittest

from lib.protocol import BaseScsyncProtocol, ErrorType, PacketType


class TestProtocol(BaseScsyncProtocol):

    def __init__(self):
        self.data = None
        self.session_id = None
        self.addr = None

    def sendto(self, data, session_id=None, addr=None):
        self.data = data
        self.session_id = session_id
        self.addr = addr


class TestPacketPackingAndUnpacking(unittest.TestCase):

    def test_error(self):
        proto = TestProtocol()

        _session_id = 42
        _filename = b'test.py'
        _filehash = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        _error_type = ErrorType.File_Hash_Error
        _error_id = 42
        proto.send_error(_session_id, _filename, _filehash, _error_type, _error_id)
        self.assertFalse(proto.data is None)
        self.assertTrue(proto.addr is None)
        self.assertEqual(proto.session_id, _session_id)
        self.assertEqual(proto.data[0:1], PacketType.Error)
        self.assertEqual(proto.data[1:33], _filehash)
        self.assertEqual(proto.data[33:35], (len(
            _filename)).to_bytes(2, byteorder='big'))
        self.assertEqual(proto.data[35:42], _filename)

        valid, filehash, filename, error_type, error_id, description = proto.unpack_error(
            proto.data[1:])
        self.assertTrue(valid)
        self.assertEqual(filehash, _filehash)
        self.assertEqual(filename, _filename)
        self.assertEqual(error_type, _error_type)
        self.assertEqual(error_id, _error_id)
        self.assertEqual(description, None)

    def test_error_description(self):
        proto = TestProtocol()

        _session_id = 42
        _filename = b'test.py'
        _filehash = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        _error_type = ErrorType.File_Hash_Error
        _error_id = 42
        _description = b'description'
        proto.send_error(_session_id, _filename, _filehash, _error_type,
                         _error_id, _description)
        self.assertFalse(proto.data is None)
        self.assertTrue(proto.addr is None)
        self.assertEqual(proto.session_id, _session_id)
        self.assertEqual(proto.data[0:1], PacketType.Error)
        self.assertEqual(proto.data[1:33], _filehash)
        self.assertEqual(proto.data[33:35], (len(
            _filename)).to_bytes(2, byteorder='big'))
        self.assertEqual(proto.data[35:42], _filename)

        valid, filehash, filename, error_type, error_id, description = proto.unpack_error(
            proto.data[1:])
        self.assertTrue(valid)
        self.assertEqual(filehash, _filehash)
        self.assertEqual(filename, _filename)
        self.assertEqual(error_type, _error_type)
        self.assertEqual(error_id, _error_id)
        self.assertEqual(description, _description)

    def test_ack_error(self):
        proto = TestProtocol()

        _session_id = 42
        _error_id = 42
        proto.send_ack_error(_session_id, _error_id)
        self.assertFalse(proto.data is None)
        self.assertTrue(proto.addr is None)
        self.assertEqual(proto.session_id, _session_id)
        self.assertEqual(proto.data[0:1], PacketType.Ack_Error)

        valid, error_id = proto.unpack_ack_error(
            proto.data[1:])
        self.assertTrue(valid)
        self.assertEqual(error_id, _error_id)

    def test_client_hello(self):
        proto = TestProtocol()

        _session_id = 42
        _epoch = 1337
        proto.send_client_update_request(_session_id, _epoch)
        self.assertFalse(proto.data is None)
        self.assertTrue(proto.addr is None)
        self.assertEqual(proto.session_id, _session_id)
        self.assertEqual(proto.data[0:1], PacketType.Client_Update_Request)

        valid, epoch = proto.unpack_client_update_request(
            proto.data[1:])
        self.assertTrue(valid)
        self.assertEqual(epoch, _epoch)

    def test_server_hello(self):
        proto = TestProtocol()

        _session_id = 42
        _fileinfos = {b'test1.py': b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                      b'test2.py': b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'}
        proto.send_current_server_state(_session_id, _fileinfos)
        self.assertFalse(proto.data is None)
        self.assertTrue(proto.addr is None)
        self.assertEqual(proto.session_id, _session_id)
        self.assertEqual(proto.data[0:1], PacketType.Current_Server_State)

        valid, fileinfos = proto.unpack_current_server_state(
            proto.data[1:])
        self.assertTrue(valid)
        self.assertEqual(fileinfos, _fileinfos)

    def test_file_metadata(self):
        proto = TestProtocol()

        _session_id = 42
        _filename = b'test.py'
        _filehash = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        _filesize = 1337
        _permissions = 0o666
        _modified_at = 42
        _fileinfo = {'filehash': _filehash,
                     'size': _filesize,
                     'permissions': _permissions,
                     'modified_at': _modified_at}
        proto.send_file_metadata(_session_id, _filename, _fileinfo)
        self.assertFalse(proto.data is None)
        self.assertTrue(proto.addr is None)
        self.assertEqual(proto.session_id, _session_id)
        self.assertEqual(proto.data[0:1], PacketType.File_Metadata)

        valid, filehash, filename, filesize, permissions, modified_at = proto.unpack_file_metadata(
            proto.data[1:])
        self.assertTrue(valid)
        self.assertEqual(filehash, _filehash)
        self.assertEqual(filename, _filename)
        self.assertEqual(filesize, _filesize)
        self.assertEqual(permissions, _permissions)
        self.assertEqual(modified_at, _modified_at)

    def test_ack_metadata(self):
        proto = TestProtocol()

        _session_id = 42
        _filename = b'test.py'
        _filehash = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        _upload_id = 1337
        _resume_at_byte = 42
        proto.send_ack_metadata(_session_id, _filehash, _filename,
                                _upload_id, _resume_at_byte)
        self.assertFalse(proto.data is None)
        self.assertTrue(proto.addr is None)
        self.assertEqual(proto.session_id, _session_id)
        self.assertEqual(proto.data[0:1], PacketType.Ack_Metadata)

        valid, filehash, filename, upload_id, resume_at_byte = proto.unpack_ack_metadata(
            proto.data[1:])
        self.assertTrue(valid)
        self.assertEqual(filehash, _filehash)
        self.assertEqual(filename, _filename)
        self.assertEqual(upload_id, _upload_id)
        self.assertEqual(resume_at_byte, _resume_at_byte)

    def test_file_upload(self):
        proto = TestProtocol()

        _session_id = 42
        _upload_id = 1337
        _start_byte = 42
        _payload = b'Hello World'
        proto.send_file_upload(_session_id, _upload_id, _start_byte, _payload)
        self.assertFalse(proto.data is None)
        self.assertTrue(proto.addr is None)
        self.assertEqual(proto.session_id, _session_id)
        self.assertEqual(proto.data[0:1], PacketType.File_Upload)

        valid, upload_id, start_byte, payload = proto.unpack_file_upload(
            proto.data[1:])
        self.assertTrue(valid)
        self.assertEqual(upload_id, _upload_id)
        self.assertEqual(start_byte, _start_byte)
        self.assertEqual(payload, _payload)

    def test_ack_upload(self):
        proto = TestProtocol()

        _session_id = 42
        _upload_id = 1337
        _acked_bytes = 42
        proto.send_ack_upload(_session_id, _upload_id, _acked_bytes)
        self.assertFalse(proto.data is None)
        self.assertTrue(proto.addr is None)
        self.assertEqual(proto.session_id, _session_id)
        self.assertEqual(proto.data[0:1], PacketType.Ack_Upload)

        valid, upload_id, acked_bytes = proto.unpack_ack_upload(proto.data[1:])
        self.assertTrue(valid)
        self.assertEqual(upload_id, _upload_id)
        self.assertEqual(acked_bytes, _acked_bytes)

    def test_file_delete(self):
        proto = TestProtocol()

        _session_id = 42
        _filename = b'test.py'
        _filehash = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        proto.send_file_delete(_session_id, _filehash, _filename)
        self.assertFalse(proto.data is None)
        self.assertTrue(proto.addr is None)
        self.assertEqual(proto.session_id, _session_id)
        self.assertEqual(proto.data[0:1], PacketType.File_Delete)

        valid, filehash, filename = proto.unpack_file_delete(proto.data[1:])
        self.assertTrue(valid)
        self.assertEqual(filehash, _filehash)
        self.assertEqual(filename, _filename)

    def test_ack_delete(self):
        proto = TestProtocol()

        _session_id = 42
        _filename = b'test.py'
        _filehash = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        proto.send_ack_delete(_session_id, _filehash, _filename)
        self.assertFalse(proto.data is None)
        self.assertTrue(proto.addr is None)
        self.assertEqual(proto.session_id, _session_id)
        self.assertEqual(proto.data[0:1], PacketType.Ack_Delete)

        valid, filehash, filename = proto.unpack_ack_delete(proto.data[1:])
        self.assertTrue(valid)
        self.assertEqual(filehash, _filehash)
        self.assertEqual(filename, _filename)

    def test_file_rename(self):
        proto = TestProtocol()

        _session_id = 42
        _old_filename = b'test1.py'
        _new_filename = b'test2.py'
        _filehash = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        proto.send_file_rename(_session_id, _filehash, _old_filename, _new_filename)
        self.assertFalse(proto.data is None)
        self.assertTrue(proto.addr is None)
        self.assertEqual(proto.session_id, _session_id)
        self.assertEqual(proto.data[0:1], PacketType.File_Rename)

        valid, filehash, old_filename, new_filename = proto.unpack_file_rename(
            proto.data[1:])
        self.assertTrue(valid)
        self.assertEqual(filehash, _filehash)
        self.assertEqual(old_filename, _old_filename)
        self.assertEqual(new_filename, _new_filename)

    def test_ack_rename(self):
        proto = TestProtocol()

        _session_id = 42
        _old_filename = b'test1.py'
        _new_filename = b'test2.py'
        _filehash = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        proto.send_ack_rename(_session_id, _filehash, _old_filename, _new_filename)
        self.assertFalse(proto.data is None)
        self.assertTrue(proto.addr is None)
        self.assertEqual(proto.session_id, _session_id)
        self.assertEqual(proto.data[0:1], PacketType.Ack_Rename)

        valid, filehash, old_filename, new_filename = proto.unpack_ack_rename(
            proto.data[1:])
        self.assertTrue(valid)
        self.assertEqual(filehash, _filehash)
        self.assertEqual(old_filename, _old_filename)
        self.assertEqual(new_filename, _new_filename)

if __name__ == '__main__':
    unittest.main()
