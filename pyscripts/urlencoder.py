#!/usr/bin/env python3

import sys
import urllib.parse

def man_page():
    help_text = """
NAME
    mytool - simple CLI tool for encoding/decoding text

SYNOPSIS
    mytool <command> <input_string>

DESCRIPTION
    A lightweight command-line tool that supports text transformations
    such as URL encoding/decoding.

COMMANDS
    -encode   Encode the given string into URL-safe format
    -decode   Decode a URL-encoded string

EXAMPLES
    mytool urlencode "hello world"
        Output: hello%20world

    mytool urldecode "hello%20world"
        Output: hello world
"""
    print(help_text)

def main():
    if len(sys.argv) < 3:
        man_page()
        sys.exit(0)

    command = sys.argv[1].lower()
    input_string = sys.argv[2]

    if command == "-encode":
        print('\n',urllib.parse.quote(input_string))
    elif command == "-decode":
        print('\n',urllib.parse.unquote(input_string))
    else:
        print(f"Unknown command: {command}")
        man_page()

if __name__ == "__main__":
    main()
