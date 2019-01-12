"""The beef of Artorias testing code"""

import importlib
from argparse import Namespace
from core.utils import *
from core.host import Host
from log import *
from core.scans.port_scan import PortScan
from core.scans.hydra_scan import HydraScan

def handle_args(args: Namespace) -> list:
    """
        Parse arguments for test and configure host objects.
    """
    # If no targets provided, assume were finding them on network.
    # Once we have targets, if no test given, port/service scan them.
    subnet = verify_subnet(args.subnet)

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


def run_scans(host: Host, scans_to_skip: list) -> None:
    """
    Checks if a host meets prerequisites for scans, and runs them. PortScan and HydraScan are
    manually run first, results from them can highly influence other scans.
    """
    low("Getting services for target {}".format(str(host)))
    port_scan = PortScan(host)
    if port_scan.requirements_met:
        port_scan.run_scan()
        host.set_services(port_scan.process_results())
    else:
        low('reqs not met??')

    debug(host.get_services())
    debug("HAS AUTH: {}".format(host.has_auth_surface()))
    debug("HAS WEB: {}".format(host.has_web_interface()))

    hydra_scan = HydraScan(host)
    if hydra_scan.requirements_met() and 'HydraScan' not in scans_to_skip:
        low("Host {} has interface for brute forcing creds, beginning scan.".format(host))
        scans_to_skip.append('hydra_scan')
        hydra_scan.run_scan()
        creds = hydra_scan.process_results()
        host.set_credentials({
            'user': creds['results'][0]['login'],
            'passwd': creds['results'][0]['password']
        })
    else:
        low("Username and password supplied, skipping auth scan.")

    # Begin dynamic scan execution
    all_scans = get_all_scans()
    scans_to_run = list(set(all_scans) - set(scans_to_skip))

    for scan in scans_to_run:
        module = importlib.import_module("core.scans.{}".format(scan))
        temp = getattr(module, file_to_class_name(scan))
        current_scan = temp(host)

        if current_scan.requirements_met():
            info("Starting {} scan.".format(temp))
            current_scan.run_scan()
        else:
            info("Requirements not met for {} scan, skipping.".format(temp))

    if host.has_web_interface():
        low("Host {} has a web interface, beginning scan.".format(host))
        # drive_web_scan(host, login_found)
        for port in host.get_services():
            if port['id'] in ['80', '443', '8080']:
                start_zap()

        debug("IP: {} Ports: {} Auth: {} \nNikto Results{} \nZap Results: {}".format(
            str(host), host.get_services(), host.get_credentials(),
            host.get_nikto_result().get_results(), host.get_zap_result().get_results()))


def handle_test(args: Namespace) -> bool:
    """
        Take care of tests..? TODO update docstring?
    """
    hosts = handle_args(args)
    skip_tests = ['host_scan', 'port_scan']

    if args.user and args.passwd:
        skip_tests.append('hydra_scan')

    # TODO research implementing Threads for this
    # Port scan
    # Auth scan
    # Threads >> point to func that inits every scan and runs them
    for host in hosts:
        run_scans(host, skip_tests)

    return True
