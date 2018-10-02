# Util Functions used within the core directory

from core.scans import host_scan

def get_hosts(subnet: str) -> list:
    """
        Perform nmap host scan and return a list of hosts on network to assess
    """
    hosts = []
    scan_info = host_scan(subnet)
    found = scan_info['nmaprun']['host']

    for host in found:
        hosts.append(host['address']['@addr'])

    return hosts

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
