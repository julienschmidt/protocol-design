#!/usr/bin/env python3
# coding: utf-8
"""
    scsynctest.module
    ~~~~~~~~~~~~~

    Tests for the assignemnt 3.

    :copyright: 2018 Andreas Ebner, Julien Schmidt, Paul Schmiedmayer
    :license: TBD
"""

import argparse
import logging
import os
import sys
import shutil
import copy
import threading
import asyncio
import time


import client
import server


# Client: scsync [-h <hostname|ip-addr>] [-p <port>] [-f <directory-path>]
# Server: scsync [-s] [-p <port>]

def create_or_clear(direcotry):
    if not os.path.exists(direcotry):
        os.makedirs(direcotry)
    else:
        for file in os.listdir(direcotry):
            file_path = os.path.join(direcotry, file)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path): shutil.rmtree(file_path)
            except Exception as e:
                print(e)


# Create a file with a given size in MB
def create_file(size, dir):
    with open(dir + '.temp/' + str(size) + 'MB.txt', 'wb') as file:
        file.write(os.urandom(1000 * 1000 * size))
        file.flush()
        os.fsync(file)
        os.rename(dir + '.temp/' + str(size) + 'MB.txt', dir + str(size) + 'MB.txt')


# UNIX Signals
def signal(self, signame) -> None:
    """
    UNIX signal handler.
    """
    print("Got signal %s: exit" % signame)
    self.stop()

def main():
    """
    Initializes the program by parsing the command-line flags and either running
    the client or the server module.
    """
    if sys.platform == 'win32':
        print("Windows is currently not supported.")
        sys.exit(1)

    # parse flags
    parser = argparse.ArgumentParser(description='Cloud Sync', conflict_handler='resolve')

    parser.add_argument('-f', dest='path', action='store',
                        default=os.getcwd(), help='directory to store the emporaty files')

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--verbose', dest='verbose', action='store_true',
                       default=False, help='verbose output')
    group.add_argument('--debug', dest='debug', action='store_true',
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

    # Create Dirs
    server_dir = args.path + 'server/'
    client_one_dir = args.path + 'client1/'
    # client_two_dir = args.path + 'client2/'

    create_or_clear(server_dir)
    create_or_clear(client_one_dir)
    create_or_clear(client_one_dir + '.temp')
    # create_or_clear(client_two_dir)

    args.test = True
    args.port = 5000
    args.cc = 5000
    args.host = 'localhost'
    args.server = True

    # Start Server
    def startServer(args):
        args.path = server_dir

        logging.info("Start Server 1")

        new_event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_event_loop)
        server.run(args)

    server_thread = threading.Thread(target=startServer, args=(copy.deepcopy(args), ))
    server_thread.start()

    time.sleep(1)

    # Start Client 1
    def startClient1(args):
        args.path = client_one_dir
        args.user = 'testuser'
        args.password = 'testpassword'
        args.server = False

        logging.info("Start Client 1")

        new_event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_event_loop)
        client.run(args)

    client_1_thread = threading.Thread(target=startClient1, args=(copy.deepcopy(args),))
    client_1_thread.start()

    time.sleep(1)

    # Uncomment to test with second client:

    # # Start Client 2
    # def startClient2(args):
    #     args.path = client_two_dir
    #     args.user = 'testuser'
    #     args.password = 'testpassword'
    #     args.server = False
    #
    #     logging.info("Start Client 2")
    #
    #     new_event_loop = asyncio.new_event_loop()
    #     asyncio.set_event_loop(new_event_loop)
    #     client.run(args)
    #
    # client_2_thread = threading.Thread(target=startClient2, args=(copy.deepcopy(args),))
    # client_2_thread.start()

    create_file(5, client_one_dir)
    # TODO: Only start next upload when previous is complete
    # TODO: Measure how much data is end and what the overhead is
    time.sleep(5)

    create_file(50, client_one_dir)
    time.sleep(50)

    create_file(100, client_one_dir)
    time.sleep(100)

    create_file(200, client_one_dir)
    time.sleep(200)

    create_file(500, client_one_dir)
    time.sleep(500)

    create_file(1000, client_one_dir)


if __name__ == "__main__":
    main()
