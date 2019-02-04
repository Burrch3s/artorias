"""
Contains Result Object Info. The scan name is returned whenever str(Results) is called,
to easily allow getting the name of the scan.
"""

class Results():
    """
        Generic object to store results of a scan
    """

    def __init__(self, scanner: str, results: dict) -> None:

        self.scanner = scanner

        self._results = results

    def __str__(self) -> str:
        return self.scanner

    def __int__(self) -> int:
        return len(self._results)

    @property
    def results(self):
        """Property for the actual results"""
        return self._results

    @results.setter
    def results(self, res: dict) -> None:
        self._results = res
