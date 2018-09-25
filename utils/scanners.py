"""Utility functions for interacting with the scanners"""

from json import dumps, loads
from utils.log import error
from xmltodict import parse

def xml2json(sfile: str) -> dict:
    """
    Take the path to a scanner XML output, and return a dict of the info.
    """
    try:
        with open(sfile, 'r') as f:
            info = f.read()
        return loads(dumps(parse(info), sort_keys=True))
    except IOError:
        error("IO Error reading {}".format(sfile))
        return None
