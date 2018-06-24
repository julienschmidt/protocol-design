# scsync - Protocol Design Project

## Requirements:
* Linux or macOS
* Python 3.5 or newer

### 3rd-party Packages:
`python3 -m pip install -r requirements.txt`

## Usage:

See `scsync --help` for all options.

### Client:
`scsync [-h <hostname|ip-addr>] [-p <port>] [-f <directory-path>] -u <username> -pass <password>`

### Server:
`scsync [-s] [-p <port>] [-f <directory-path>] [-cc]` 

#### User Credentials
For each user a password hash and salt have to be generated using the `tools/gen_user_vkey.py` script.

The credentials are then stored as CSV using the format `<username>,<salt>,<verification_key>` in the `users.csv`.

**ATTENTION**: By default a "testuser" with password "testpassword" is configured, which should be replaced by proper user credentials!

### Arguments:
`-s` Server mode: accept incoming connections from any host
`-p` Specify the port number (default: `5000`)
`-f` Directory that should be used to upload (client mode) or store the files (server mode)
`-h` Remote hosts
`-cc` Packets per second
`--verbose` Enable logging of most events
`--debug` Enable debug logging, all events are logged
