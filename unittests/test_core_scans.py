import unittest
from unittest.mock import call, patch, MagicMock
from core.scanning import *

class TestCoreScanning(unittest.TestCase):

    @patch('core.scanning.low')
    @patch('core.scanning.Popen')
    @patch('core.scanning.datetime')
    def test_host_scan(self, mock_time, mock_popen, mock_low):
        mock_time.now.return_value.strftime.return_value = 'MockTime'
        ret = host_scan('MockSubnet')

        expected_calls = [
            call(['nmap', 'MockSubnet', '-sn', '-oX', 'core/outputs/host_scanMockTime.xml'],
                 stderr=-3, stdout=-3),
            call().wait()
        ]
        for c in expected_calls:
            self.assertIn(c, mock_popen.mock_calls)

        self.assertEquals(mock_low.call_count, 2)
        self.assertEquals(ret, 'core/outputs/host_scanMockTime.xml')

    @patch('core.scanning.low')
    @patch('core.scanning.Popen')
    @patch('core.scanning.datetime')
    def test_skipfish_scan(self, mock_date, mock_popen, mock_low):
        mock_date.now.return_value.strftime.return_value = 'MockTime'

        ret = skipfish_scan('MockHost', 'MockPort')
        expected_calls = [
            call(['skipfish', '-o', 'core/outputs/skipfish_scanMockPort_MockTime.xml',
                  'MockHost']),
            call().wait()
        ]
        for c in expected_calls:
            self.assertIn(c, mock_popen.mock_calls)

        self.assertEquals(ret, 'core/outputs/skipfish_scanMockPort_MockTime.xml')

