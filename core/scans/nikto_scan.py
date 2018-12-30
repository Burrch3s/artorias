"""Default template of a scan"""

# Generic imports to utilize
from datetime import datetime
from subprocess import Popen, DEVNULL
from core.host import Host
from core.result import Results
from core.scan import Scan
from core.utils import xml2json
from log import low
from settings import SCAN_OUTPUT_DIR, DATE_ARGS

class NiktoScan(Scan):

    def __init__(self, target: Host) -> None:
        super().__init__(target)

    def requirements_met(self) -> bool:
        """
        Checks if a host has a web interface
        """
        return self.target.has_web_interface()

    def set_config(self, *args: list, **kwargs: dict) -> None:
        if 'port' in kwargs:
            self.port = kwargs['port']
        if 'user' in kwargs and 'password' in kwargs:
            self.user = kwargs['user']
            self.password = kwargs['password']

    def run_scan(self) -> None:
        """
        Perform actual scan. It is absolutely ok to implement other functions to help
        run_scan and reduce complexity.
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
