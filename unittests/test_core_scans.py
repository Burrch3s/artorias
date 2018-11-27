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
                 stderr=-3, stdout=-3),
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
            call(['nmap', 'MockSubnet', '-oX', 'core/outputs/port_scanMockTime.xml'], stderr=-3, stdout=-3),
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

        self.assertEquals(ret, 'core/outputs/nikto_scanMockPort_MockTime.xml')

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
        for c in expected_calls:
            self.assertIn(c, mock_popen.mock_calls)

        self.assertEquals(ret, 'core/outputs/nikto_scanMockPort_MockTime.xml')

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

        self.assertEquals(ret, 'core/outputs/skipfish_scanMockPort_MockTime.xml')

    @patch('core.scans.low')
    @patch('core.scans.Popen')
    @patch('core.scans.warning')
    @patch('core.scans.datetime')
    def test_hydra_scan(self, mock_date, mock_warning, mock_popen, mock_low):
        mock_date.now.return_value.strftime.return_value = 'MockTime'

        ret = hydra_scan('MockHost', 22, 'ssh')
        expected_calls = [
            call(['hydra', '-L', 'scanners/rockyou.txt', '-P', 'scanners/rockyou.txt',
                  '-u', '-f', '-o', 'core/outputs/hydra_scanssh_MockTime.json', '-b',
                  'json', 'ssh://MockHost']),
            call().wait()
        ]

        for c in expected_calls:
            self.assertIn(c, mock_popen.mock_calls)

        self.assertEquals(ret, 'core/outputs/hydra_scanssh_MockTime.json')


    @patch('core.scans.low')
    @patch('core.scans.ZAPv2')
    def test_zep_setup_context(self, mock_zap, mock_low):
        mock_zap.return_value.context.new_context.return_value = 'mock_context'
        mock_zap.return_value.users.new_user.return_value = 'mock_user'

        context, user = zap_setup_context('MockHost', 'MockPort', 'MockUser', 'MockPw')

        self.assertEquals(context, 'mock_context')
        self.assertEquals(user, 'mock_user')

        expected_calls = [
            call().context.new_context('ZapScan'),
            call().context.include_in_context('ZapScan', 'MockHost.*'),
            call().context.include_in_context('ZapScan', 'http://MockHost.*'),
            call().authentication.set_authentication_method(
                'mock_context', 'httpAuthentication', 'hostname=MockHost&realm='),
            call().users.new_user('mock_context', 'zapuser'),
            call().users.set_authentication_credentials(
                'mock_context', 'mock_user', 'username=MockUser&password=MockPw'),
            call().users.set_user_enabled('mock_context', 'mock_user', True),
            call().forcedUser.set_forced_user('mock_context', 'mock_user'),
            call().forcedUser.set_forced_user_mode_enabled(True)
        ]

        for c in expected_calls:
            self.assertIn(c, mock_zap.mock_calls)

    @patch('core.scans.sleep')
    @patch('core.scans.datetime')
    @patch('builtins.open')
    @patch('core.scans.low')
    @patch('core.scans.ZAPv2')
    def test_zap_spider(self, mock_zap, mock_low, mock_open, mock_time, mock_sleep):
        mock_zap.return_value.spider.status.return_value = 100
        mock_zap.return_value.pscan.records_to_scan = 0
        mock_zap.return_value.spider.scan.return_value = 'MockScan'
        mock_time.now.return_value.strftime.return_value = 'MockTime'

        ret = zap_spider('MockHost', '443')
        self.assertEqual(ret, 'core/outputs/zap_spider_MockTime.json')

        expected_calls = [
            call(),
            call().urlopen('https://MockHost'),
            call().spider.scan('https://MockHost'),
            call().spider.status('MockScan'),
            call().core.jsonreport()
        ]

        for c in expected_calls:
            self.assertIn(c, mock_zap.mock_calls)

    @patch('builtins.open')
    @patch('core.scans.datetime')
    @patch('core.scans.sleep')
    @patch('core.scans.low')
    @patch('core.scans.ZAPv2')
    @patch('core.scans.zap_setup_context')
    def test_zap_spider_auth(self,
                             mock_setup,
                             mock_zap,
                             mock_low,
                             mock_sleep,
                             mock_time,
                             mock_open):

        mock_setup.return_value = ('mock_context', 'mock_user')
        mock_time.now.return_value.strftime.return_value = 'MockTime'
        mock_zap.return_value.spider.scan_as_user.return_value = 'MockId'
        mock_zap.return_value.spider.status.return_value = 100
        mock_zap.return_value.pscan.records_to_scan = 0

        ret = zap_spider_auth('MockHost', '443', 'MockUser', 'MockPw')
        self.assertEquals(ret, 'core/outputs/zap_spider_MockTime.json')

        expected_calls = [
            call().urlopen('https://MockHost'),
            call().spider.scan_as_user('mock_context', 'mock_user', 'https://MockHost'),
            call().spider.status('MockId'),
            call().core.jsonreport()
        ]

        for c in expected_calls:
            self.assertIn(c, mock_zap.mock_calls)
