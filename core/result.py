# Contains Result Object Info

class Results():
    """
        Generic object to store results of a scan
    """

    def __init__(self, scanner='', results=[]):

        self.scanner = scanner

        self._results = results

    def __str__(self):
        return self.scanner

    def __int__(self):
        return len(self._results)

    def get__results(self):
        return self._results

    def set_results(self, res):
        self._results = res

