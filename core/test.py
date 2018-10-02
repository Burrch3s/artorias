"""The beef of Artorias testing code"""

from argparse import Namespace
from core.scans import host_scan
from core.utils import get_hosts, verify_subnet

def handle_test(args: Namespace) -> bool:
    """
        Take care of tests..? TODO update docstring?
    """
    # If not targets, assume were finding them on network
    # Once we have targets, if no test given, port/service scan them
    # Depending on what services found or test given,, do stuff

    hosts = args.target
    subnet = verify_subnet(args.subnet)

    if not args.target:
        hosts = get_hosts(subnet)

    print(hosts, subnet)
    return True
