# Util Functions used within the core directory

from xmltodict import parse
from json import dumps, loads
from core.host import Host
from core.result import Results
from core.scans import *
from log import *

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

    debug("port_info {}".format(port_info))
    return port_info


def drive_web_scan(host: Host, auth: bool) -> None:
    """
    Automate web app scanners against the provided host
    """
    common_ports = ['80', '443', '8080']

    for port in host.get_services():
        if port['id'] in common_ports:
            # TODO replace with standardized and filtered nikto/skipfish results
            if not auth:
                host.set_nikto_result(Results('nikto', xml2json(nikto_scan(host, port['id']))))
                host.skipfish_result(Results('skipfish', xml2json(skipfish_scan(host, port['id']))))
            else:
                creds = host.get_credentials()
                host.set_nikto_result(
                    Results('nikto', xml2json(
                        nikto_scan_auth(host, port['id'], creds['user'], creds['passwd']))))

def drive_auth_scan(host: Host) -> bool:
    """
    Automate hydra auth scan against the provided host
    """
    hydra_ports = {
        '80': 'http',
        '443': 'https',
        '21': 'ftp',
        '22': 'ssh',
        '23': 'telnet'
    }

    for port in host.get_services():
        if port['id'] in hydra_ports:
            debug("{} {}".format(port, port['id']))
            fname = hydra_scan(host, port['id'], hydra_ports[port['id']])
            try:
                with open(fname) as f:
                    creds = loads(f.read())

                user = creds['results'][0]['login']
                pw = creds['results'][0]['password']
                host.set_credentials({'user': user, 'passwd': pw})
            except Exception as e:
                error("Error occurred: {}. Unable to get credentials.".format(e))
                return False

            return True

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
