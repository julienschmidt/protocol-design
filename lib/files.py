from os import listdir
from os.path import isfile, join

def list(path):
    return [f.encode('utf8') for f in listdir(path) if isfile(join(path, f))]
