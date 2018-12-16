# Contains Result Object Info

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

    def get_results(self) -> dict:
        return self._results

    def set_results(self, res: dict) -> None:
        self._results = res

