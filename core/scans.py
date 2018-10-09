# Contains scan functions

from datetime import datetime
from subprocess import Popen
from log import low
from settings import SCAN_OUTPUT_DIR

def host_scan(subnet: str) -> dict:
    """
        Drive nmap host scan, save output to a file and return output from xml2json
    """
    # File name to save output to
    fname = '{}/host_scan{}.xml'.format(SCAN_OUTPUT_DIR, datetime.now().strftime('%m-%d_%H-%M-%S'))

    # Drive host scan and output to file
    nmap = Popen(['nmap', subnet, '-sn', '-oX', fname], stdout=None)
    low("Waiting for host scan to complete.")

    nmap.wait()

    low("Host scan completed.")
    return fname

def port_scan(target: str) -> dict:
    """
        Drive nmap port scan, save output to a file and return output from xml2json.
        No fancy args here, just default port scan for now.
    """
    # File name to save output to
    fname = '{}/port_scan{}.xml'.format(SCAN_OUTPUT_DIR, datetime.now().strftime('%m-%d_%H-%M-%S'))

    # Drive host scan and output to file
    nmap = Popen(['nmap', str(target), '-oX', fname])
    low("Waiting for port scan to complete.")

    nmap.wait()

    low("Port scan completed.")
    return fname
