# Contains Host Object Info

from core.result import Results

class Host():
    """
        Object containing references to individual host specific variables
        and methods.
    """

    def __init__(self, ip: str) -> None:

        self._ip = ip

        self._services = None

        self._open_ports = []

        self._nikto_result = None

        self._zap_result = None

        self._credentials = {}

    def __str__(self) -> str:
        return self._ip

    def get_ip(self) -> str:
        return self._ip

    def get_services(self) -> Results:
        return self._services

    def get_nikto_result(self) -> Results:
        return self._nikto_result

    def get_zap_result(self) -> Results:
        return self._zap_result

    def get_credentials(self) -> dict:
        return self._credentials

    def get_open_ports(self) -> list:
        return self._open_ports

    def set_ip(self, ip: str) -> None:
        self._ip = ip

    def set_services(self, services: list) -> None:
        self._services = services

    def set_nikto_result(self, result: Results) -> None:
        self._nikto_result = result

    def set_zap_result(self, result: Results) -> None:
        self._zap_result = result

    def set_credentials(self, creds: dict) -> None:
        self._credentials.update(creds)

    def set_open_ports(self, ports: list) -> None:
        self._open_ports = ports

    def has_web_interface(self) -> bool:
        """
        Determine if host has a port that is commonly known as a web interface
        """
        for service in self._services.get_results()['ports']:
            if service['id'] in ('80', '443', '8080'):
                return True
        return False

    def has_auth_surface(self) -> bool:
        """
        Determine if host has ports/services suitable to run brute force against for
        credentials.
        """
        auth = ['80', '443', '21', '22', '23']
        for service in self._services.get_results()['ports']:
            if service['id'] in auth:
                return True
        return False
