import unittest
from unittest.mock import patch, MagicMock
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

    @patch('core.utils.xml2json')
    @patch('core.utils.port_scan')
    def test_get_services(self, mock_port, mock_xml):
        mock_xml.return_value = {
            'nmaprun': {
                'host': {
                    'ports': {
                        'port': [{
                            '@portid': '22',
                            'service': {'@name': 'ssh'},
                            'state': {'@state': 'open'},
                        }]
                    }
                }
            }
        }

        ret = get_services('MockHost')
        self.assertEquals(
            ret, {'ports': [{'state': 'open', 'id': '22', 'name': 'ssh'}]})

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
