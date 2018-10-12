import unittest
from unittest.mock import call, patch, MagicMock
from core.scans import *

class TestCoreScans(unittest.TestCase):

    @patch('core.scans.low')
    @patch('core.scans.Popen')
    @patch('core.scans.datetime')
    def test_host_scan(self, mock_time, mock_popen, mock_low):
        mock_time.now.return_value.strftime.return_value = 'MockTime'
        ret = host_scan('MockSubnet')

        expected_calls = [
            call(['nmap', 'MockSubnet', '-sn', '-oX', 'core/outputs/host_scanMockTime.xml'],
                 stdout=None),
            call().wait()
        ]
        for c in expected_calls:
            self.assertIn(c, mock_popen.mock_calls)

        self.assertEquals(mock_low.call_count, 2)
        self.assertEquals(ret, 'core/outputs/host_scanMockTime.xml')

    @patch('core.scans.low')
    @patch('core.scans.Popen')
    @patch('core.scans.datetime')
    def test_port_scan(self, mock_time, mock_popen, mock_low):
        mock_time.now.return_value.strftime.return_value = 'MockTime'
        ret = port_scan('MockSubnet')

        expected_calls = [
            call(['nmap', 'MockSubnet', '-oX', 'core/outputs/port_scanMockTime.xml']),
            call().wait()
        ]
        for c in expected_calls:
            self.assertIn(c, mock_popen.mock_calls)

        self.assertEquals(mock_low.call_count, 2)
        self.assertEquals(ret, 'core/outputs/port_scanMockTime.xml')

    @patch('core.scans.low')
    @patch('core.scans.Popen')
    @patch('core.scans.datetime')
    def test_nikto_scan(self, mock_date, mock_popen, mock_low):
        mock_date.now.return_value.strftime.return_value = 'MockTime'

        ret = nikto_scan('MockHost', 'MockPort')
        expected_calls = [
            call(['nikto', '-host', 'MockHost', '-port', 'MockPort', '-output',
                  'core/outputs/nikto_scanMockPort_MockTime.xml']),
            call().wait()
        ]
        for c in expected_calls:
            self.assertIn(c, mock_popen.mock_calls)

    @patch('core.scans.low')
    @patch('core.scans.Popen')
    @patch('core.scans.datetime')
    def test_nikto_scan_auth(self, mock_date, mock_popen, mock_low):
        mock_date.now.return_value.strftime.return_value = 'MockTime'

        ret = nikto_scan_auth('MockHost', 'MockPort', 'MockUser', 'MockPW')
        expected_calls = [
            call(
                ['nikto', '-host', 'MockHost', '-port', 'MockPort', '-id',
                 'MockUser:MockPW', '-output', 'core/outputs/nikto_scanMockPort_MockTime.xml']),
                           call().wait()
        ]

    @patch('core.scans.low')
    @patch('core.scans.Popen')
    @patch('core.scans.datetime')
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
