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

    def __str__(self):
        return self.ip

