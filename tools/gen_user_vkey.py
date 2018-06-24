#!/usr/bin/env python3
# coding: utf-8

import base64

import srp


def main():
    username = input("Enter username: ")
    password = input("Enter password: ")
    salt, vkey = srp.create_salted_verification_key(username, password)

    print()
    print("Add the following line to the users.csv:")
    print()
    print("%s,%s,%s" % (username, base64.b64encode(salt).decode(
        'utf-8'), base64.b64encode(vkey).decode('utf-8')))

if __name__ == "__main__":
    main()
