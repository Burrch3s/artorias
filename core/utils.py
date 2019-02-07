"""Util Functions used within the core directory"""

from importlib import import_module
from os import listdir
from xmltodict import parse
from json import dumps, loads
from time import sleep
from retrying import retry
from subprocess import Popen, DEVNULL
from core.host import Host
from core.result import Results
from log import *
from zapv2 import ZAPv2

def get_hosts(subnet: str) -> list:
    """
        Perform nmap host scan and return a list of hosts on network to assess
    """
    hosts = []
    scan_info = xml2json(host_scan(subnet))
    found = scan_info['nmaprun']['host']

    for device in found:
        hosts.append(Host(device['address']['@addr']))

    return hosts

@retry(stop_max_attempt_number=60, wait_fixed=1000)
def wait_for_zap():
    """
    Wait until the python api is able to interact with the zaproxy application.
    If after retries it doesnt work, raise zap error.
    """
    zap = ZAPv2()
    zap.urlopen('http://127.0.0.1')
    sleep(3)


def start_zap():
    """
    Start up the Zaproxy application so the python API can communicate with it.
    """
    try:
        zap = ZAPv2()
        zap.urlopen('http://127.0.0.1')
    except:
        low("Starting the zaproxy application.")
        Popen(['zaproxy'], stdout=DEVNULL, stderr=DEVNULL)
        wait_for_zap()

def zap_setup_context(target: Host, port: str, user: str, passwd: str) -> tuple:
    """
    Creates a context for this scan, adding a new user to that context and sets up
    the authentication mechanism.
    """
    zap = ZAPv2()

    if port == '443':
        url = "https://{}".format(str(target))
    else:
        url = "http://{}".format(str(target))

    low("Creating new context for zap scan.")
    context_id = zap.context.new_context("ZapScan")

    # Default listening for zap is 8090
    zap.context.include_in_context("ZapScan", "{}.*".format(str(target)))
    zap.context.include_in_context("ZapScan", "{}.*".format(url))
    zap.authentication.set_authentication_method(
        context_id, 'httpAuthentication', 'hostname={}&realm='.format(str(target)))

    low("Creating user for context.")
    user_id = zap.users.new_user(context_id, "zapuser")
    zap.users.set_authentication_credentials(
        context_id, user_id, "username={}&password={}".format(user, passwd))
    zap.users.set_user_enabled(context_id, user_id, True)

    zap.forcedUser.set_forced_user(context_id, user_id)
    zap.forcedUser.set_forced_user_mode_enabled(True)

    return context_id, user_id

def verify_subnet(subnet: str) -> str:
    """
        Verify and return valid subnet
    """
    if len(subnet.split('.')) != 4:
        return ''
    if len(subnet.split('/')) != 2:
        return ''
    return subnet

def xml2json(sfile: str) -> dict:
    """
    Take the path to a scanner XML output, and return a dict of the info.
    """
    try:
        with open(sfile, 'r') as f:
            info = f.read()
        return loads(dumps(parse(info), sort_keys=True))
    except IOError:
        error("IO Error reading {}".format(sfile))
        return None

def get_all_scans() -> list:
    """
    Get names of Python files in core/scans directory and drop the file suffix
    """
    return [scan.split('.')[0] for scan in listdir('./core/scans') if scan.endswith('.py')]

def file_to_class_name(f_name: str) -> str:
    """
    Take the file name of a scan and return the name of it as a class: snake to camel case
    """
    return "".join(word.title() for word in f_name.split('_'))

def run_scans(host: Host, scans_to_run: list, force: bool = False) -> None:
    """
    Checks if a host meets prerequisites for scans, and runs them.
    """
    # TODO research implementing Threads for this
    # TODO add fault tolerance
    #
    # Iterate over all available tests in the core/scans directory
    # Import the module from core.scans, then the class from the module
    # and finally initialize the class, passing the host to scan.
    for scan in scans_to_run:
        module = import_module("core.scans.{}".format(scan))
        temp = getattr(module, file_to_class_name(scan))
        current_scan = temp(host)

        if current_scan.requirements_met() and not force:
            current_scan.set_config()
            low("Starting {} scan.".format(temp))
            current_scan.run_scan()
            host.scans = current_scan.process_results()
        elif force:
            current_scan.set_config()
            warning("Forcing {} scan to run.".format(temp))
            current_scan.run_scan()
            host.scans = current_scan.process_results()
        else:
            low("Requirements not met for {} scan, skipping.".format(temp))

def host_scan(subnet: str) -> str:
    """
        Drive nmap host scan, save output to a file and return output file name.
    """
    # File name to save output to
    fname = '{}/host_scan{}.xml'.format(SCAN_OUTPUT_DIR, datetime.now().strftime('%m-%d_%H-%M-%S'))

    # Drive host scan and output to file
    nmap = Popen(['nmap', subnet, '-sn', '-oX', fname], stdout=DEVNULL, stderr=DEVNULL)
    low("Waiting for host scan to complete.")

    nmap.wait()

    low("Host scan completed.")
    return fname

def skipfish_scan(target: Host, port: str) -> str:
    """
        DEPRECATED: TODO re-evaulate it's worth, then potentially create Scan
        Drive Skipfish scan against a specified port, save output to a file and return
        outpu file name.
    """
    # File name to save output to
    fname = '{}/skipfish_scan{}_{}.xml'.format(SCAN_OUTPUT_DIR, port, datetime.now().strftime(
        '%m-%d_%H-%M-%S'))

    skipfish = Popen(['skipfish', '-o', fname, str(target)])
    low('Waiting for Skipfish scan on port {} to complete.'.format(port))

    skipfish.wait()

    low('Skipfish scan completed.')
    return fname

def zap_quickurl(target: Host, port: str) -> str:
    """
        OWASP-Zap scan to quickly scan web app elements. Uses the zaproxy command in cmd mode.
    """
    return
