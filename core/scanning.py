"""
TODO implement execution of select scans from core/scans and perhaps implement interactive
shell for that
TODO remove scans
"""

from datetime import datetime
from time import sleep
from json import dumps, loads
from subprocess import Popen, DEVNULL
from zapv2 import ZAPv2
from core.host import Host
from log import *
from settings import SCAN_OUTPUT_DIR, WORD_LIST

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
