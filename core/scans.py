# Contains scan functions

from datetime import datetime
from subprocess import Popen
from core.host import Host
from log import low
from settings import SCAN_OUTPUT_DIR, WORD_LIST

def host_scan(subnet: str) -> str:
    """
        Drive nmap host scan, save output to a file and return output file name.
    """
    # File name to save output to
    fname = '{}/host_scan{}.xml'.format(SCAN_OUTPUT_DIR, datetime.now().strftime('%m-%d_%H-%M-%S'))

    # Drive host scan and output to file
    nmap = Popen(['nmap', subnet, '-sn', '-oX', fname], stdout=None)
    low("Waiting for host scan to complete.")

    nmap.wait()

    low("Host scan completed.")
    return fname

def port_scan(target: str) -> str:
    """
        Drive nmap port scan, save output to a file and return output file name.
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

def nikto_scan(target: Host, port: str) -> str:
    """
        Drive Nikto scan against a specified port, save output to a file and return
        output file name.
    """
    # File name to save output to
    fname = '{}/nikto_scan{}_{}.xml'.format(SCAN_OUTPUT_DIR, port, datetime.now().strftime(
        '%m-%d_%H-%M-%S'))

    nikto = Popen(['nikto', '-host', str(target), '-port', port, '-output', fname])
    low('Waiting for Nikto scan on port {} to complete'.format(port))

    nikto.wait()

    low('Nikto scan completed.')
    return fname

def nikto_scan_auth(target: Host, port: str, user: str, pw: str) -> str:
    """
        Nikto scan with auth supplied, saves output to a file and returns the file name
    """
    # File name to save output to
    fname = '{}/nikto_scan{}_{}.xml'.format(SCAN_OUTPUT_DIR, port, datetime.now().strftime(
        '%m-%d_%H-%M-%S'))

    nikto = Popen(['nikto', '-host', str(target), '-port', port, '-id', '{}:{}'.format(user, pw),
                   '-output', fname])
    low('Waiting for Nikto with auth scan on port {} to complete.'.format(port))

    nikto.wait()

    low('Nikto scan with auth completed.')
    return fname

def skipfish_scan(target: Host, port: str) -> str:
    """
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

def hydra_scan(target: Host, service: str) -> str:
    """
        Hydra scan to retrieve brute force credentials
    """
    # File name to save output to
    fname = '{}/hydra_scan{}_{}.xml'.format(SCAN_OUTPUT_DIR, service, datetime.now().strftime(
        '%m-%d_%H-%M-%S'))

    hydra = Popen([
        'hydra', '-L', WORD_LIST, '-P', WORD_LIST, '-u', '-f', '-o', fname,
        "-b", "json", "{}://{}".format(str(target), service)])
    low('Waiting for hydra scan on {} to complete.'.format(service))

    hydra.wait()

    low('Hydra scan completed.')
    return fname

def zap_quickurl(target: Host, port: str) -> str:
    """
        OWASP-Zap scan to quickly scan web app elements. Uses the zaproxy command in cmd mode.
    """
    return

def zap_spider(target: Host, port: str) -> str:
    """
        TODO implement with Zap API
    """
    return
