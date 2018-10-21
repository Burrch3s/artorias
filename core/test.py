"""The beef of Artorias testing code"""

from argparse import Namespace
from core.utils import *
from core.host import Host

def handle_test(args: Namespace) -> bool:
    """
        Take care of tests..? TODO update docstring?
    """
    # If not targets, assume were finding them on network
    # Once we have targets, if no test given, port/service scan them
    # Depending on what services found or test given,, do stuff

    subnet = verify_subnet(args.subnet)

    if not args.target:
        hosts = get_hosts(subnet)
    else:
        hosts = [Host(host) for host in args.target]

    # TODO research implementing Threads for this
    for host in hosts:
        host.services = get_services(host)['ports']

        if host.has_web_interface():
            drive_web_scan(host)

    return True
