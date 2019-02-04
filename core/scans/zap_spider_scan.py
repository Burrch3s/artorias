"""Default template of a scan"""

# Generic imports to utilize
from time import sleep
from json import loads
from datetime import datetime
from subprocess import Popen, DEVNULL
from zapv2 import ZAPv2
from core.host import Host
from core.result import Results
from core.scan import Scan
from core.utils import xml2json, start_zap, wait_for_zap, zap_setup_context
from log import low
from settings import SCAN_OUTPUT_DIR, DATE_ARGS

class ZapSpiderScan(Scan):

    def __init__(self, target: Host) -> None:
        super().__init__(target)

    def requirements_met(self) -> bool:
        """
        Check to be performed if the target meets requirements
        """
        return self.target.has_web_interface()

    def set_config(self) -> None:
        try:
            self.user = self.target.credentials['user']
            self.password = self.target.credentials['passwd']
        except KeyError:
            low("No USER/PASS provided for zap scan, running without them.")
            self.user = ""
            self.password = ""

        for temp in self.target.open_ports:
            if temp in ('80', '8080', '443'):
                self.port = temp
                break

    def run_scan(self) -> None:
        """
        Perform actual scan. It is absolutely ok to implement other functions to help
        run_scan and reduce complexity.
        """
        start_zap()
        zap = ZAPv2()
        self.output_name = '{}/nikto_scan{}_{}.xml'.format(SCAN_OUTPUT_DIR, self.port,
                                                           datetime.now().strftime(DATE_ARGS))

        if self.port == '443':
            url = "https://{}".format(str(self.target))
        else:
            url = "http://{}".format(str(self.target))

        low("Beginning zap spider on {}".format(url))
        zap.urlopen(url)
        sleep(1)

        if self.user and self.password:
            context_id, user_id = zap_setup_context(self.target, self.port, self.user, self.password)
            spider_id = zap.spider.scan_as_user(context_id, user_id, url)
        else:
            spider_id = zap.spider.scan(url)


        # Scanning as user, just in case forced user mode is wonky
        sleep(1)
        low("Waiting for scan to complete".format(url))
        while int(zap.spider.status(spider_id)) < 100:
            sleep(1)

        low("Spider scan complete.")
        low("Collecting any alerts from spider.")
        while int(zap.pscan.records_to_scan) > 0:
            sleep(1)

        low("Alerts collected.")

        json = zap.core.jsonreport()
        self.output_name = '{}/zap_spider_{}.json'.format(SCAN_OUTPUT_DIR, datetime.now().strftime(
            '%m-%d_%H-%M-%S'))

        with open(self.output_name, "w") as f:
            f.write(json)

    def process_results(self) -> Results:
        """
        Strip out unneeded information and create Results object for scan
        """
        with open(self.output_name, 'r') as temp:
            results = loads(temp.read())

        return Results('zap_spide_scan', results)
