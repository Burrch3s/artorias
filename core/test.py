"""The beef of Artorias testing code"""

from argparse import Namespace
from core.utils import *
from core.host import Host
from log import *

def handle_args(args: Namespace) -> list:
    """
        Parse arguments for test and configure host objects.
    """
    # If not targets, assume were finding them on network
    # Once we have targets, if no test given, port/service scan them.
    # Depending on what services found or test given,, do stuff
    subnet = verify_subnet(args.subnet)

    # Handle arguments supplied
    if not args.target:
        low("Target not supplied, running host scan.")
        hosts = get_hosts(subnet)
    else:
        low("Target supplied: {}".format(args.target))
        hosts = [Host(host) for host in args.target]

    if args.user and args.passwd:
        low("Username and Password supplied for tests, {}:{}".format(args.user, args.passwd))
        for host in hosts:
            host.set_credentials({'user': args.user, 'passwd': args.passwd})

    return hosts


def handle_test(args: Namespace) -> bool:
    """
        Take care of tests..? TODO update docstring?
    """
    hosts = handle_args(args)

    # TODO research implementing Threads for this
    for host in hosts:
        low("Getting services for target {}".format(str(host)))
        host.set_services(get_services(host)['ports'])

        debug(host.get_services())
        debug("HAS AUTH: {}".format(host.has_auth_surface()))
        debug("HAS WEB: {}".format(host.has_web_interface()))
        if host.has_auth_surface() and not (args.user and args.passwd):
            low("Host {} has interface for brute forcing creds, beginning scan.".format(host))
            login_found = drive_auth_scan(host)
        else:
            low("Username and password supplied, skipping auth scan.")
            login_found = True

        debug(host.has_web_interface())
        if host.has_web_interface():
            low("Host {} has a web interface, beginning scan.".format(host))
            drive_web_scan(host, login_found)

        debug("IP: {} Ports: {} Auth: {} Nikto Results{} \nZap Results: {}".format(
            str(host), host.get_services(), host.get_credentials(),
            host.get_nikto_result().get_results(), host.get_zap_result().get_results()))

    return True
