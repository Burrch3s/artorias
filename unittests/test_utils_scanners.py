
import unittest
from unittest.mock import patch, MagicMock
from utils.scanners import *

class TestScanners(unittest.TestCase):

    @patch('utils.scanners.parse')
    @patch('utils.scanners.error')
    @patch('utils.scanners.loads')
    @patch('utils.scanners.dumps')
    @patch('builtins.open')
    def test_xml2json(self, mock_open, mock_dumps, mock_loads, mock_error, mock_parse):
        mock_dumps.return_value = 'moreMocks'
        mock_loads.return_value = 'moreMocks'
        mock_parse = 'moreMocks'

        # Test bad file raises and returns None
        mock_open.side_effect = IOError()
        res = xml2json('mockFile')

        self.assertRaises(IOError)
        self.assertEquals(res, None)
        self.assertEquals(mock_open.call_count, 1)

        # Test good file read
        mock_open.return_value = 'mockMocks'
        res = xml2json('mockFile')

        self.assertEquals(res, None)
        self.assertEquals(mock_open.call_count, 2)
