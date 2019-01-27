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
        'scanScans': "Scans to run, either singular or a list of them.",
        'scanPorts': "Ports that the target has to run scans on.",
        'scanCredentials': "<user>:<password> combintation to use on targets authenticated services.",
        'test': "Run a series of scans, preconfigured to test aspects of an IoT host." \
                + "The recommended option to using this scanner/framework",
        'testAll': "Run all tests possible",
        'testTarget': "Target(s) to run tests on",
        'testSubnet': 'Instead of individual targets, specify network to identify hosts on.',
        'testUser': 'Username to use for authenticating with services. Must be supplied with password.',
        'testPass': 'Password to use for authticating with services. Must be supplied with username.',
        'testOutput': 'Log file to output logging information to. Default is scanner.log',
        'testLog': 'Lowest log level to display. Set to debug to output debug messages to file.',

    }

    parser = argparse.ArgumentParser()

    # Command agnostic arguments
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="scanner.log",
        help=msg['testOutput'])
    parser.add_argument(
        "-l",
        "--log_level",
        type=str,
        default="info",
        choices=["info", "debug", "warning", "error"],
        help=msg['testLog'])

    subparser = parser.add_subparsers(
        dest="command",
        help=msg['subparser'])
    subparser.required = True

    # artorias scan ${args}
    scan = subparser.add_parser(
        "scan",
        help=msg['scan'])
    scan.add_argument(
        "-s",
        "--scans",
        type=list,
        choices=['nikto', 'hydra', 'zap-spider'],
        help=msg['scanScans'])
    scan.add_argument(
        "-p",
        "--ports",
        type=list,
        help=msg['scanPorts'])
    scan.add_argument(
        "-c",
        "--credentials",
        type=str,
        help=msg['scanCredentials'])

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
    test.add_argument(
        "-u",
        "--user",
        type=str,
        default=None,
        help=msg['testUser'])
    test.add_argument(
        "-p",
        "--passwd",
        type=str,
        default=None,
        help=msg['testPass'])

    return parser.parse_args()
