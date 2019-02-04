"""Hydra scan to test host for generic credentials"""

# Generic imports to utilize
from datetime import datetime
from subprocess import Popen, DEVNULL
from json import loads
from core.host import Host
from core.result import Results
from core.scan import Scan
from core.utils import xml2json
from log import low, warning, error
from settings import SCAN_OUTPUT_DIR, DATE_ARGS, WORD_LIST, AUTH_PORTS

class HydraScan(Scan):

    def __init__(self, target: Host) -> None:
        super().__init__(target)

        # TODO need to update these, hydra throws errors about type of requests!
        #'80': 'http',
        #'443': 'https',
        # Translate ports to services
        self.hydra_ports = {
            '21': 'ftp',
            '22': 'ssh',
            '23': 'telnet'
        }

    def requirements_met(self) -> bool:
        """
        Checks if a host has a auth interface
        """
        return self.target.has_auth_surface()

    def set_config(self) -> None:
        for temp in self.target.get_open_ports():
            if temp in self.hydra_ports:
                port = temp
                break

        try:
            self.service = self.hydra_ports[port]
        except KeyError:
            error("No port to service translation for {}".format(port))
            raise

    def run_scan(self) -> None:
        """
        Perform actual scan. It is absolutely ok to implement other functions to help
        run_scan and reduce complexity.
        """
        # File name to save output to
        self.output_name = '{}/hydra_scan{}_{}.json'.format(SCAN_OUTPUT_DIR, self.service, datetime.now().strftime(
            '%m-%d_%H-%M-%S'))

        try:
            warning("Brute forcing credentials can take a long time, consider running with creds.")
            hydra = Popen([
                'hydra', '-L', WORD_LIST, '-P', WORD_LIST, '-u', '-f', '-o', self.output_name,
                "-b", "json", "{}://{}".format(self.service, str(self.target))])

            low('Waiting for hydra scan on {} to complete.'.format(self.service))
            hydra.wait()
        except KeyboardInterrupt:
            low("Hydra scan aborted. Other scans may not be as effective without credentials.")

        low('Hydra scan completed.')

    def process_results(self) -> Results:
        """
        Strip out unneeded information and create Results object for scan
        """
        with open(self.output_name) as f:
            creds = f.read()

        return Results('hydra', loads(creds))
