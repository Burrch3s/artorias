"""Perform nikto web app scan"""

# Generic imports to utilize
from datetime import datetime
from subprocess import Popen, DEVNULL
from core.host import Host
from core.result import Results
from core.scan import Scan
from core.utils import xml2json
from log import low
from settings import SCAN_OUTPUT_DIR, DATE_ARGS, WEB_PORTS

class NiktoScan(Scan):

    def __init__(self, target: Host) -> None:
        super().__init__(target)

    def requirements_met(self) -> bool:
        """
        Checks if a host has a web interface
        """
        return self.target.has_web_interface()

    def set_config(self) -> None:
        try:
            self.user = self.target.credentials['user']
            self.password = self.target.credentials['passwd']
        except KeyError:
            low("User/Pass not supplied for nikto scan, running without credentials.")
            self.user = ""
            self.password = ""

        for temp in self.target.open_ports:
            if temp in WEB_PORTS:
                self.port = temp
                break

    def run_scan(self) -> None:
        """
        Runs actual nikto web app scan with basic args
        """
        self.output_name = '{}/nikto_scan{}_{}.xml'.format(SCAN_OUTPUT_DIR, self.port, datetime.now().strftime(
            DATE_ARGS))

        # This scanner can be helpful with stdout since it doesnt flood logs and can
        # be polled for progress of the scan
        low('Waiting for Nikto scan on port {} to complete'.format(self.port))
        if self.user and self.password:
            nikto = Popen(['nikto', '-host', str(self.target), '-port',
                           self.port, '-id', '{}:{}'.format(self.user, self.password),
                           '-output', self.output_name])
        else:
            nikto = Popen(['nikto', '-host', str(self.target), '-port', self.port, '-output', self.output_name])

        nikto.wait()
        low('Nikto scan completed.')

    def process_results(self) -> Results:
        """
        Strip out unneeded information and create Results object for scan
        """
        # TODO implement stripping of unneeded info, formatting
        return Results('nikto_scan', xml2json(self.output_name))
