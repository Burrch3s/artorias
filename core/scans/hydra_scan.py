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

class HydraScan(Scan):

    def __init__(self, target: Host) -> None:
        super().__init__(target)

    def requirements_met(self) -> bool:
        """
        Checks if a host has a auth interface
        """
        return self.target.has_auth_interface()

    def run_scan(self) -> None:
        """
        Perform actual scan. It is absolutely ok to implement other functions to help
        run_scan and reduce complexity.
        """
        # File name to save output to
        fname = '{}/hydra_scan{}_{}.json'.format(SCAN_OUTPUT_DIR, service, datetime.now().strftime(
            '%m-%d_%H-%M-%S'))

        try:
            warning("Brute forcing credentials can take a long time, CTRL-C once to abort.")
            hydra = Popen([
                'hydra', '-L', WORD_LIST, '-P', WORD_LIST, '-u', '-f', '-o', fname,
                "-b", "json", "{}://{}".format(service, str(target))])

            low('Waiting for hydra scan on {} to complete.'.format(service))
            hydra.wait()
        except KeyboardInterrupt:
            low("Hydra scan aborted. Other scans may not be as effective without credentials.")

        low('Hydra scan completed.')
        return fname

    def process_results(self) -> Results:
        """
        Strip out unneeded information and create Results object for scan
        """
        return None
