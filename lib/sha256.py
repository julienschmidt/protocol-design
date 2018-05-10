import binascii
import hashlib

def hash(data):
    m = hashlib.sha256()
    m.update(data)
    return m.digest()

def hash_file(filepath):
    f = open(filepath, 'rb')
    return hash(f.read())

def hex(h):
    return binascii.hexlify(h)
