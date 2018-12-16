""" Scan object to layout basic template of creating a scan"""

from core.result import Results
from log import low

# x = PortScan(['192.158.0.0', '127.0.0.1'])
# x.set_config(port=99)
# list of Hosts or str

class Scan:
    """
    Parent class representing a scan or test.
    """

    def __init__(self, targets: list):

        # Remote host to scan
        self.target = targets

        # Filename of scanner output
        self.output_name = ''

        # Any scanner specific configurations to be set
        self.config = {}

    def requirements_met(self) -> bool:
        """
        Return bool whether or not the scan can be run, depending on any requirements
        being met.
        """
        pass

    def set_config(self, *args: list, **kwargs: dict) -> None:
        """
        Scanner specific function for settings any paramenters needed to complete the test:
        example would be ports to scan, user names, passwords, etc.
        """
        pass

    def run_scan(self) -> None:
        """
        Perform actual scan and output results to a file for processing or formatting.
        """
        pass

    def process_results(self) -> Results:
        """
        Perform any formatting of results from file and return Results object.
        """
        pass
