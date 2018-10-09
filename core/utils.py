# Util Functions used within the core directory

from xmltodict import parse
from json import dumps, loads
from core.host import Host
from core.scans import host_scan, port_scan
from log import error

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

def get_services(host: str) -> dict:
    """
        Perform nmap service scan and return a list of services/ports listening
    """
    scan_info = xml2json(port_scan(host))
    ports = scan_info['nmaprun']['host']['ports']['port']
    port_info = {
        'ports': []
    }

    for port in ports:
        tmp = {}
        tmp['id'] = port['@portid']
        tmp['name'] = port['service']['@name']
        tmp['state'] = port['state']['@state']
        port_info['ports'].append(tmp)

    return port_info

def verify_subnet(subnet: str) -> str:
    """
        Verify and return valid subnet
    """
    if len(subnet.split('.')) != 4:
        return ''
    elif len(subnet.split('/')) != 2:
        return ''
    else:
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
