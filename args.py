"""Contains all of the argument definitions for Artorias"""

import argparse

def parse_cmd() -> argparse.Namespace:
    """
        Using argparse and subparsers, gather the command the
        user wishes to invoke. Subparsers are used since I believe
        it makes commands clearer and provides context to args.
    """
    msg = {
        "subparser": "Choose what to do with Artorias",
        'identify': "Identify hosts on specified subnet",
        'scan': "Run a scanner with default args, manually testing on an IoT host with",
        'scanHostScan': "Nmap host scan: Searches current network for alive hosts",
        'test': "Run a series of scans, preconfigured to test aspects of an IoT host." \
                + "The recommended option to using this scanner/framework",
        'testAll': "Run all tests possible",
        'testTarget': "Target(s) to run tests on",
        'testSubnet': 'Instead of individual targets, specify network to identify hosts on.',
        'service': "Start WebInterface Service to show/represent results"
    }

    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(
        dest="command",
        help=msg['subparser'])
    subparser.required = True

    # artorias scan ${args}
    scan = subparser.add_parser(
        "scan",
        help=msg['scan'])
    scan.add_argument(
        "--hostScan",
        action="store_true",
        help=msg['scanHostScan'])

    # artorias test ${args}
    test = subparser.add_parser(
        "test",
        help=msg['test'])
    test.add_argument(
        "-a",
        "--all",
        action='store_true',
        help=msg['testAll'])
    test.add_argument(
        "-t",
        "--target",
        nargs='+',
        type=str,
        default=[],
        help=msg['testTarget'])
    test.add_argument(
        "-s",
        "--subnet",
        nargs='?',
        type=str,
        default='192.168.0.0/24',
        help=msg['testSubnet'])

    return parser.parse_args()
