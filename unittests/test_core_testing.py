import unittest
from unittest.mock import call, patch, MagicMock
from core.testing import *

class TestCoreTesting(unittest.TestCase):

    @patch('core.testing.Host')
    @patch('core.testing.low')
    @patch('core.testing.get_hosts')
    @patch('core.testing.verify_subnet')
    def test_handle_args(self, mock_sub, mock_get, mock_low, mock_host):
        args= MagicMock()
        args.target = ['mock1', 'mock2']
        args.user = ""
        args.passwd = ""

        # Test with target supplied
        hosts = handle_args(args)
        self.assertEquals(len(hosts), 2)

        # Test without target and with creds
        args.user = 'user'
        args.passwd = 'passwd'
        args.target = ''
        host = MagicMock()
        mock_get.return_value = [host]

        hosts = handle_args(args)
        mock_get.assert_called_with(mock_sub(args.subnet))
        host.set_credentials.assert_called_with({'user': args.user, 'passwd': args.passwd})
        self.assertEquals(len(hosts), 1)

    def test_prereq_scans(self):
        # TODO update
        pass

    def test_run_scans(self):
        # TODO update
        pass

    def test_handle_test(self):
        # TODO update
        pass
