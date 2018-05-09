# csync - Protocol Design Project

## Requirements:
* Linux or macOS
* Python 3.4 or newer

### 3rd-party Packages:
`pip3 install watchdog`

## Usage:

See `csync --help` for all options.

### Client: 
`csync [-h <hostname|ip-addr>] [-p <port>] [-f <directory-path>]`  

### Server: 
`csync [-s] [-p <port>] [-f <directory-path>]`

### Arguments:
`-s` Server mode: accept incoming connections from any host  
`-p` Specify the port number (default: `5000`)  
`-f` Upload all files in that directory to the server  
`-h` Remote hosts
