# Contains Host Object Info

from core.result import Results

class Host():
    """
        Object containing references to individual host specific variables
        and methods.
    """

    def __init__(self, ip=''):

        self._ip = ip

        self._services = {}

        self._open_ports = []

        self._nikto_result = None

        self._skipfish_result = None

    def __str__(self):
        return self.ip

    def get_ip(self) -> str:
        return self._ip

    def set_ip(self, ip: str) -> None:
        self._ip = ip

    def get_services(self) -> dict:
        return self._services

    def set_services(self, services: dict) -> None:
        self._services = services

    def get_nikto_result(self) -> Results:
        return self._nikto_result

    def set_nikto_result(self, result: Results) -> None:
        self._nikto_result = result

    def get_skipfish_result(self) -> Results:
        self._skipfish_result = result

    def has_web_interface(self) -> bool:
        """
        Determine if host has a port that is commonly known as a web interface
        """
        for service in self.services:
            if service['id'] in ('80', '443', '8080'):
                return True
        return False
