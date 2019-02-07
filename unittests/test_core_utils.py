import unittest
from unittest.mock import call, patch, MagicMock
from core.utils import *

class TestCoreUtils(unittest.TestCase):

    @patch('core.utils.xml2json')
    @patch('core.utils.Host')
    @patch('core.utils.host_scan')
    def test_get_hosts(self, mock_scan, mock_host, mock_xml):
        mock_xml.return_value = {
            'nmaprun': {
                'host': [{
                    'address': {
                        '@addr': '127.0.0.1'
                    }
                }]
            }
        }
        mock_host.return_value = 'MockHost'

        ret = get_hosts('MockSubnet')
        self.assertEquals(ret, ['MockHost'])


    def test_verify_subnet(self):
        # Test with no subnet notation
        ret = verify_subnet('1.1.1.1')
        self.assertEquals(ret, '')

        # Test with no IP notation
        ret = verify_subnet('/24')
        self.assertEquals(ret, '')

        # Test with good ip/subnet notation
        ret = verify_subnet('1.1.1.1/24')
        self.assertEquals(ret, '1.1.1.1/24')

    @patch('core.utils.parse')
    @patch('core.utils.error')
    @patch('core.utils.loads')
    @patch('core.utils.dumps')
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

    @patch('core.utils.low')
    @patch('core.utils.Popen')
    @patch('core.utils.wait_for_zap')
    @patch('core.utils.ZAPv2')
    def start_zap(self, mock_zap, mock_wait, mock_popen, mock_low):
        # Test starting zap with no exception correctly opens url
        start_zap()

        mock_low.assert_not_called()
        mock_popen.assert_not_called()

        # Test when zap not up, correctly start up and wait for zap
        mock_zap.return_value.urlopen.side_effect = BaseException

        start_zap()
        mock_low.assert_called()
        mock_popen.assert_called()
        mock_wait.assert_called()

    @patch('core.utils.low')
    @patch('core.utils.ZAPv2')
    def test_zap_setup_context(self, mock_zap, mock_low):
        # TODO update unittest: include checks on internal func calls
        # convinience variables
        con = mock_zap.return_value.context
        user = mock_zap.return_value.users
        force = mock_zap.return_value.forcedUser
        auth = mock_zap.return_value.authentication

        con.new_context.return_value = 'c_id'
        user.new_user.return_value = 'u_id'

        c_id, u_id = zap_setup_context('host', '80', 'user', 'pass')

        self.assertEquals(c_id, 'c_id')
        self.assertEquals(u_id, 'u_id')

    @patch('core.utils.wait_for_zap')
    @patch('core.utils.Popen')
    @patch('core.utils.low')
    @patch('core.utils.ZAPv2')
    def test_start_zap(self, mock_zap, mock_low, mock_popen, mock_wait):
        start_zap()
        mock_zap().urlopen.assert_called_with('http://127.0.0.1')
        self.assertEquals(len(mock_popen.mock_calls), 0)
        self.assertEquals(len(mock_wait.mock_calls), 0)

        mock_zap.return_value.urlopen.side_effect = IOError
        start_zap()
        self.assertEquals(len(mock_popen.mock_calls), 1)
        self.assertEquals(len(mock_wait.mock_calls), 1)

    def test_run_scans(self):
        # Need to come up with a good way of testing this function..
        # reading the docs seems to show that it may not be possible to patch the
        # use of us calling getattr() in the actual run_scans function:
        # https://docs.python.org/3/library/unittest.mock.html
        pass
