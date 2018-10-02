# Contains scan functions

from subprocess import Popen
from datetime import datetime
from utils.log import low
from utils.scanners import xml2json
from settings import SCAN_OUTPUT_DIR

def host_scan(subnet: str) -> dict:
    """
        Drive nmap host scan, save output to a file and return output from xml2json
    """
    # File name to save output to
    fname = '{}/host_scan{}.xml'.format(SCAN_OUTPUT_DIR, datetime.now().strftime('%m-%d_%H-%M-%S'))

    # Drive host scan and output to file
    nmap = Popen(['nmap', subnet, '-sn', '-oX', fname])
    low("Waiting for host scan to complete.")
    nmap.wait()

    # call xml2json on output file
    return xml2json(fname)

def port_scan(target: str) -> dict:
    """
        Drive nmap port scan, save output to a file and return output from xml2json
    """
    # File name to save output to
    fname = 'core/outputs'

    # Drive host scan and output to file
    nmap = Popen(['nmap', target, '-sL', '-oX', fname])
    low("Waiting for host scan to complete.")
    nmap.wait()

    # call xml2json on output file
    return xml2json('core/outputs/host_scan{}.xml'.format(t))
