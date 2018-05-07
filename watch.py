import sys
import time

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from lib import sha256

class FileEventHandler(FileSystemEventHandler):
    def __init__(self):
        print("FileHandler init")

    def on_created(self, event):
        if event.is_directory:
            return

        print("created", event.src_path)
        sha256.hashFile(event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return

        print("deleted", event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return

        print("modified", event.src_path)
        sha256.hashFile(event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return

        print("moved", event.src_path, event.dest_path)
        sha256.hashFile(event.src_path)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else '.'
    event_handler = FileEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()





