"""The beef of Artorias testing code. Handles the test argument passed when calling artorias"""

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
    if not args.target:
        low("Target not supplied, running host scan.")
        hosts = get_hosts(verify_subnet(args.subnet))
    else:
        low("Target supplied: {}".format(args.target))
        hosts = [Host(host) for host in args.target]

    if args.user and args.passwd:
        low("Username and Password supplied for tests, {}:{}".format(args.user, args.passwd))
        for host in hosts:
            host.credentials = {'user': args.user, 'passwd': args.passwd}

    return hosts

def prereq_scans(host: Host, scans_to_skip: list) -> None:
    """
    PortScan and HydraScan are needed to run first, results from them highly influence
    scans that follow after.
    """
    low("Getting services for target {}".format(str(host)))
    port_scan = PortScan(host)
    if port_scan.requirements_met:
        port_scan.run_scan()
        host.services = port_scan.process_results().results
        host.open_ports = [port['id'] for port in host.services['ports']]
    else:
        low('Prerequisites not met for PortScan.')
        return

    debug(host.services)
    debug("HAS AUTH: {}".format(host.has_auth_surface()))
    debug("HAS WEB: {}".format(host.has_web_interface()))

    hydra_scan = HydraScan(host)
    if hydra_scan.requirements_met() and 'hydra_scan' not in scans_to_skip:
        low("Host {} has interface for brute forcing creds, beginning scan.".format(host))
        scans_to_skip.append('hydra_scan')
        hydra_scan.set_config()
        hydra_scan.run_scan()
        creds = hydra_scan.process_results()
        host.credentials = {
            'user': creds['results'][0]['login'],
            'passwd': creds['results'][0]['password']
        }
    else:
        low("Username and password supplied, skipping auth scan.")

def handle_test(args: Namespace) -> bool:
    """
    Handle test command, running all scans
    """
    hosts = handle_args(args)
    skip_tests = ['host_scan', 'port_scan']

    if args.user and args.passwd:
        skip_tests.append('hydra_scan')

    debug(skip_tests)

    # Begin dynamic scan execution
    all_scans = get_all_scans()
    scans_to_run = list(set(all_scans) - set(skip_tests))

    for host in hosts:
        # Port scan, Auth scan
        prereq_scans(host, skip_tests)
        run_scans(host, scans_to_run)

    return True
