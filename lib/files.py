from os import listdir
from os.path import isfile, join, relpath

def list(path):
    return [f for f in listdir(path) if isfile(join(path, f))]

def relative_filepath(file, basedir):
    return relpath(file, basedir).encode('utf8')
