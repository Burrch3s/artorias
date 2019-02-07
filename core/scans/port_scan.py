"""nmap scan to get open ports of a host"""

from datetime import datetime
from subprocess import Popen, DEVNULL
from core.host import Host
from core.result import Results
from core.scan import Scan
from core.utils import xml2json
from log import low
from settings import SCAN_OUTPUT_DIR, DATE_ARGS

class PortScan(Scan):

    def __init__(self, target: Host) -> None:
        super().__init__(target)

    def requirements_met(self) -> bool:
        if not isinstance(self.target, Host):
            return False

        return True

    def run_scan(self) -> None:
        """
        Perform nmap port scan and suppress output
        """
        self.output_name = '{}/port_scan{}.xml'.format(SCAN_OUTPUT_DIR,
                                                       datetime.now().strftime(DATE_ARGS))

        nmap = Popen(['nmap', str(self.target), '-oX', self.output_name],
                     stdout=DEVNULL, stderr=DEVNULL)

        low("Waiting for port scan on {} to complete".format(str(self.target)))
        nmap.wait()
        low("Port scan on {} completed.".format(str(self.target)))

    def process_results(self) -> Results:
        """
        Take only the necessary info out of scan result: the port number, name and state
        """
        scan_info = xml2json(self.output_name)
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

        return Results('port_scan', port_info)
