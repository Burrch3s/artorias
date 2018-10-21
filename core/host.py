# Contains Host Object Info

class Host():
    """
        Object containing references to individual host specific variables
        and methods.
    """

    def __init__(self, ip=''):

        self.ip = ip

        self.services = {}

        self.open_ports = []

        self.nikto_result = None

        self.skipfish_result = None

    def __str__(self):
        return self.ip

    def has_web_interface(self) -> bool:
        """
        Determine if host has a port that is commonly known as a web interface
        """
        for service in self.services:
            if service['id'] in ('80', '443', '8080'):
                return True
        return False
