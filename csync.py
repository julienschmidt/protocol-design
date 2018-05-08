#!/usr/bin/env python3

import argparse
import os
import sys

import client
import server

# Client: csync [-h <hostname|ip-addr>] [-p <port>] [-f <directory-path>]
# Server: csync [-s] [-p <port>]

def main():
    # parse flags
    parser = argparse.ArgumentParser(description='Cloud Sync', conflict_handler='resolve')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-h', dest='host', action='store', default='localhost', help='remote host (hostname or IP address)')
    group.add_argument('-s', dest='server', action='store_true', default=False, help='run in server mode')

    parser.add_argument('-p', dest='port', action='store', default=5000, type=int, help='port number')
    parser.add_argument('-f', dest='path', action='store', default=os.getcwd(), help='directory path containing files')

    args = parser.parse_args()

    # normalize path
    if args.path[0] != '/' and args.path[0] != '.':
        args.path = os.getcwd()+'/'+args.path
    args.path = os.path.normpath(args.path)+'/'

    if args.server:
        server.run(args)
    else:
        client.run(args)

if __name__ == "__main__":
    main()
