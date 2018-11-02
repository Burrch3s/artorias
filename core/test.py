"""The beef of Artorias testing code"""

from argparse import Namespace
from core.utils import *
from core.host import Host
from log import *

def handle_test(args: Namespace) -> bool:
    """
        Take care of tests..? TODO update docstring?
    """
    # If not targets, assume were finding them on network
    # Once we have targets, if no test given, port/service scan them
    # Depending on what services found or test given,, do stuff

    subnet = verify_subnet(args.subnet)

    if not args.target:
        low("Target not supplied, running host scan.")
        hosts = get_hosts(subnet)
    else:
        low("Target supplied: {}".format(args.target))
        hosts = [Host(host) for host in args.target]

    # TODO research implementing Threads for this
    for host in hosts:
        low("Getting services for target {}".format(str(host)))
        host.set_services(get_services(host)['ports'])

        debug(host.get_services())
        debug(host.has_auth_surface())
        if host.has_auth_surface():
            low("Host {} has interface for brute forcing creds, beginning scan.".format(host))
            login_found = drive_auth_scan(host)

        debug(host.has_web_interface())
        if host.has_web_interface():
            low("Host {} has a web interface, beginning scan.".format(host))
            drive_web_scan(host, login_found)

    return True
