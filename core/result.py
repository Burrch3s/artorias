# Contains Result Object Info

class Results():
    """
        Generic object to store results of a scan
    """

    def __init__(self, scanner=''):

        self.scanner = scanner

        self.result = []

    def __str__(self):
        return self.scanner

    def __int__(self):
        return len(self.result)
