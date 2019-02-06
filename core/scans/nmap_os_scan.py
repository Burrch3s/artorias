"""Default template of a scan"""

# Generic imports to utilize
from os import geteuid
from datetime import datetime
from subprocess import Popen, DEVNULL
from core.host import Host
from core.result import Results
from core.scan import Scan
from core.utils import xml2json
from log import low
from settings import SCAN_OUTPUT_DIR, DATE_ARGS

class NmapOsScan(Scan):

    def __init__(self, target: Host) -> None:
        super().__init__(target)

    def requirements_met(self) -> bool:
        """
        Check that the user is run as root; nmap OS scan requires root privileges
        """
        return geteuid() == 0

    def run_scan(self) -> None:
        """
        Perform nmap OS fingerprint scan
        """
        self.output_name = '{}/os_scan{}.xml'.format(SCAN_OUTPUT_DIR,
                                                       datetime.now().strftime(DATE_ARGS))

        nmap = Popen(['nmap', str(self.target), '-O', '-oX', self.output_name],
                     stdout=DEVNULL, stderr=DEVNULL)

        low("Waiting for OS fingerprint scan on {} to complete".format(str(self.target)))
        nmap.wait()
        low("OS fingerprint scan on {} completed.".format(str(self.target)))

    def process_results(self) -> Results:
        """
        Take only the necessary info out of scan result: OS type, kernel version
        """
        scan_info = xml2json(self.output_name)
        print(scan_info)
        os_res = scan_info['nmaprun']['host']['os']
        os_info = {
            'os': []
        }

        return Results('os_scan', os_info)
