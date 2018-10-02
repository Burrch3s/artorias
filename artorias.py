#!/usr/bin/env python

"""Artorias main file"""

from args import parse_cmd
from core.test import handle_test

def main() -> int:
    """
        Call parse_cmd and hand off execution accordingly
    """
    arguments = parse_cmd()
    cmd = arguments.command
    if cmd == 'test':
        ret = handle_test(arguments)
    elif cmd == 'scan':
        ret = handle_scan(arguments)

    exit(int(ret))

if __name__ == "__main__":
    main()
