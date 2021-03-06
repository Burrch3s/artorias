# Contains Host Object Info

from core.result import Results
from settings import WEB_PORTS, AUTH_PORTS

class Host():
    """
        Object containing references to individual host specific variables
        and methods.
    """

    def __init__(self, ip: str) -> None:

        self._ip = ip

        self._services = None

        self._open_ports = None

        self._credentials = {}

        self._scans = list()

    def __str__(self) -> str:
        return self._ip

    @property
    def ip(self) -> str:
        """IP of the host being scanned"""
        return self._ip

    @ip.setter
    def ip(self, new_ip: str) -> None:
        self._ip = new_ip

    @property
    def services(self) -> Results:
        """Raw results of services up from PortScan"""
        return self._services

    @services.setter
    def services(self, services: list) -> None:
        self._services = services

    @property
    def credentials(self) -> dict:
        """Credentials, user/passwd for authentication with the host"""
        return self._credentials

    @credentials.setter
    def credentials(self, creds: dict) -> None:
        self._credentials.update(creds)

    @property
    def open_ports(self) -> list:
        """List of the available port numbers open or to use on scans"""
        return self._open_ports

    @open_ports.setter
    def open_ports(self, ports: list) -> None:
        self._open_ports = ports

    @property
    def scans(self) -> list:
        """List of Results from scans on the host"""
        return self._scans

    @scans.setter
    def scans(self, new_scan):
        self._scans.append(new_scan)

    def has_web_interface(self) -> bool:
        """
        Determine if host has a port that is commonly known as a web interface
        """
        for port in self._open_ports:
            if port in WEB_PORTS:
                return True
        return False

    def has_auth_surface(self) -> bool:
        """
        Determine if host has ports/services suitable to run brute force against for
        credentials.
        """
        for port in self._open_ports:
            if port in AUTH_PORTS:
                return True
        return False
