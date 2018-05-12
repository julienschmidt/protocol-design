import binascii
import hashlib

def hash(data):
    m = hashlib.sha256()
    m.update(data)
    return m.digest()

def hash_file(filepath):
    m = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(8192)
            if not data:
                break
            m.update(data)
    return m.digest()

def hex(h):
    return binascii.hexlify(h)
