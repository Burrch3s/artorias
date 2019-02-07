import unittest
from unittest.mock import call, patch, MagicMock
from core.scanning import *

class TestCoreScanning(unittest.TestCase):

    @patch('core.scanning.run_scans')
    @patch('core.scanning.handle_args')
    def test_handle_scan(self, mock_handle, mock_run):
        args = MagicMock()
        args.scans = ['scan_1', 'scan_2']
        host_1 = MagicMock()
        host_2 = MagicMock()
        mock_handle.return_value = [host_1, host_2]

        ret = handle_scan(args)

        self.assertEquals(mock_run.call_count, 2)
        calls = [
            call(host_1, args.scans, True),
            call(host_2, args.scans, True)
        ]

        for c in calls:
            self.assertIn(c, mock_run.mock_calls)

    @patch('core.scanning.warning')
    @patch('core.scanning.Host')
    @patch('core.scanning.low')
    def test_handle_args(self, mock_low, mock_host, mock_warn):
        host = MagicMock()
        mock_host.return_value = host

        args = MagicMock()
        args.credentials = False
        args.target = [MagicMock()]
        args.ports = ['22', '23']

        ret = handle_args(args)
        self.assertEquals(ret, [host])
        self.assertEquals(ret[0].open_ports, ['22', '23'])

        args.credentials = 'wrongformat'
        ret = handle_args(args)
        self.assertEquals(len(mock_warn.mock_calls), 1)
        self.assertEquals(ret, [host])

        args.credentials = 'mockuser:mockpw'
        ret = handle_args(args)
        self.assertEquals(ret, [host])
        self.assertEquals(ret[0].credentials['user'], 'mockuser')
        self.assertEquals(ret[0].credentials['passwd'], 'mockpw')
