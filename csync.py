#!/usr/bin/env python3

import argparse
import os
import sys

import logging
import client
import server


# Client: csync [-h <hostname|ip-addr>] [-p <port>] [-f <directory-path>]
# Server: csync [-s] [-p <port>]

def main():
    if sys.platform == 'win32':
        print("Windows is currently not supported.")
        exit(1)

    # parse flags
    parser = argparse.ArgumentParser(
        description='Cloud Sync', conflict_handler='resolve')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-h', dest='host', action='store',
                       default='localhost', help='remote host (hostname or IP address)')
    group.add_argument('-s', dest='server', action='store_true',
                       default=False, help='run in server mode')

    parser.add_argument('-p', dest='port', action='store',
                        default=5000, type=int, help='port number')
    parser.add_argument('-f', dest='path', action='store',
                        default=os.getcwd(), help='directory path containing files')

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-verbose', dest='verbose',
                       action='store_true', default=False, help='verbose output')
    group.add_argument('-debug', dest='debug', action='store_true',
                       default=False, help='verbose debug output')

    args = parser.parse_args()

    # normalize path
    args.path = os.path.abspath(args.path) + '/'

    # Logging Modes
    level = logging.WARNING
    if args.verbose:
        level = logging.INFO
    elif args.debug:
        level = logging.DEBUG
    logging.basicConfig(format='[%(levelname)s] %(message)s', level=level)

    # Start Program
    if args.server:
        server.run(args)
    else:
        client.run(args)

if __name__ == "__main__":
    main()
