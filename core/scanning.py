"""
TODO implement execution of select scans from core/scans and perhaps implement interactive
shell for that
TODO remove scans
"""

from argparse import Namespace
from datetime import datetime
from subprocess import Popen, DEVNULL
from core.host import Host
from core.utils import file_to_class_name, run_scans
from log import low, warning, error
from settings import SCAN_OUTPUT_DIR, WORD_LIST

def handle_scan(args: Namespace) -> bool:
    """
    Handle execution of scan arg, running one or more scans from user input.
    """
    hosts = handle_args(args)

    # For each scan, force scan to run. Reason for force is that we don't want a scan to not run
    # from users specified ports not belonging in the WEB/AUTH variables for some scans.
    for host in hosts:
        run_scans(host, args.scans, True)

    return True

def handle_args(args: Namespace) -> list:
    """
    Parse arguments for scan and configure host objects. The scan arg is more demanding about
    the information it requires before it will run tests, and will not attempt to dynamically
    figure out information about the target before running a scan.
    """
    low("Target supplied: {}".format(args.target))
    hosts = [Host(host) for host in args.target]

    if args.credentials:
        if len(args.credentials.split(':')) != 2:
            warning("Credentials should be as supplied <USER>:<PASS>")
            low("Defaulting to no credentials")
        else:
            low("User and Password supplied for scans, {}".format(args.credentials))
            for host in hosts:
                host.set_credentials({'user': args.credentials.split(':')[0],
                                      'passwd': args.credentials.split(':')[1]})

    for host in hosts:
        host.set_open_ports(args.ports)

    return hosts
