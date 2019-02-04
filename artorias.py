#!/usr/bin/env python

"""
Artorias main file, kicks off the rest of the project. Either run scan(s) individually with
the scan arg, or run all of them with the test arg.
"""

import logging
from core.args import parse_cmd
from core.testing import handle_test
from core.scanning import handle_scan

def main() -> int:
    """
    Call parse_cmd and hand off execution accordingly
    """
    arguments = parse_cmd()

    # Convert arg from parser/user_input to proper log levels
    log_level = getattr(logging, arguments.log_level.upper())
    logging.basicConfig(filename=arguments.output, level=log_level)
    cmd = arguments.command

    if cmd == 'test':
        ret = handle_test(arguments)
    elif cmd == 'scan':
        ret = handle_scan(arguments)

    exit(int(ret))

if __name__ == "__main__":
    main()
