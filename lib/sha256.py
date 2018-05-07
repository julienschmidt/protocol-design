import binascii
import hashlib

def hash(data):
    m = hashlib.sha256()
    m.update(data)
    return m.digest()

def hashFile(filepath):
    f = open(filepath, 'rb')
    m = hashlib.sha256()
    m.update(f.read())
    return m.digest()

def hex(h):
    return binascii.hexlify(h)
