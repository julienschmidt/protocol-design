from os import listdir
from os.path import isfile, join, relpath

def list(path):
    return [f.encode('utf8') for f in listdir(path) if isfile(join(path, f))]

def relative_path(filepath, basedir):
    return relpath(filepath, basedir).encode('utf8')
