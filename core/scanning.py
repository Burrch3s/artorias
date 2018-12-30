# Contains scan functions

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

def zap_setup_context(target: Host, port: str, user: str, passwd: str) -> tuple:
    """
    Creates a context for this scan, adding a new user to that context and sets up
    the authentication mechanism.
    """
    zap = ZAPv2()

    if port == '443':
        url = "https:{}".format(str(target))
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

def zap_quickurl(target: Host, port: str) -> str:
    """
        OWASP-Zap scan to quickly scan web app elements. Uses the zaproxy command in cmd mode.
    """
    return

def zap_spider(target: Host, port: str) -> str:
    """
        Zap spider scan of web interface
    """
    zap = ZAPv2()

    if port == '443':
        url = "https://{}".format(str(target))
    else:
        url = "http://{}".format(str(target))

    low("Beginning zap spider on {}".format(url))
    zap.urlopen(url)
    sleep(1)

    # Scanning as user, just in case forced user mode is wonky
    spider_id = zap.spider.scan(url)
    sleep(1)
    low("Waiting for scan to complete".format(url))
    while int(zap.spider.status(spider_id)) < 100:
        sleep(1)

    low("Spider scan complete.")
    low("Collectint any alerts from spider.")
    while int(zap.pscan.records_to_scan) > 0:
        sleep(1)

    low("Alerts collected.")

    json = zap.core.jsonreport()
    fname = '{}/zap_spider_{}.json'.format(SCAN_OUTPUT_DIR, datetime.now().strftime(
        '%m-%d_%H-%M-%S'))

    with open(fname, "w") as f:
        f.write(json)

    return fname

def zap_spider_auth(target: Host, port: str, user: str, passwd: str) -> str:
    """
        Zap spider scan with auth.
    """
    if port == '443':
        url = "https://{}".format(str(target))
    else:
        url = "http://{}".format(str(target))

    context_id, user_id = zap_setup_context(target, port, user, passwd)

    zap = ZAPv2()

    low("Beginning zap spider on {}".format(url))
    zap.urlopen(url)
    sleep(1)

    # TODO consider making this wait more smart
    spider_id = zap.spider.scan_as_user(context_id, user_id, url)

    sleep(1)
    low("Waiting for scan to complete".format(url))
    while int(zap.spider.status(spider_id)) < 100:
        sleep(1)

    low("Spider scan complete.")
    low("Collectint any alerts from spider.")
    while int(zap.pscan.records_to_scan) > 0:
        sleep(1)

    low("Alerts collected.")

    json = zap.core.jsonreport()
    fname = '{}/zap_spider_{}.json'.format(SCAN_OUTPUT_DIR, datetime.now().strftime(
        '%m-%d_%H-%M-%S'))

    with open(fname, "w") as f:
        f.write(json)

    return fname
