# scsync - Protocol Design Project

## Requirements:
* Linux or macOS
* Python 3.5 or newer

### 3rd-party Packages:
`pip3 install aiofiles watchdog`

## Usage:

See `scsync --help` for all options.

### Client:
`scsync [-h <hostname|ip-addr>] [-p <port>] [-f <directory-path>]`

### Server:
`scsync [-s] [-p <port>] [-f <directory-path>]`

### Arguments:
`-s` Server mode: accept incoming connections from any host
`-p` Specify the port number (default: `5000`)
`-f` Directory that should be used to upload (client mode) or store the files (server mode)
`-h` Remote hosts
`--verbose` Enable logging of most events
`--debug` Enable debug logging, all events are logged
