import unittest
from AppInspector.pcap_tdroid_matcher import parse_logs, http_taints, parse_dir
from utils import set_logger

logger = set_logger('TestPcapTaintDroidMatcher', 'DEBUG')


class TestPcapTaintDroidMatcher(unittest.TestCase):
    def test_parse_logs(self):
        taints, pkg = parse_logs('0897d40edb8b6b585f38ca1a9866bd03cd70a5035cc0ec28f933d702f9a38a03')
        self.assertEqual(pkg, 'com.gp.mahjongg')
        self.assertEqual(len(taints), 4)
        for taint in taints:
            logger.debug(taint)
            self.assertEqual(taint['process_name'], 'com.gp.mahjongg')
            self.assertEqual(taint['channel'], 'HTTP')

    def test_http_taints(self):
        taints, pkg = parse_logs('0897d40edb8b6b585f38ca1a9866bd03cd70a5035cc0ec28f933d702f9a38a03')
        tgt_taints = http_taints(taints)
        self.assertEqual(len(tgt_taints), 4)
        for taint in tgt_taints:
            logger.debug(taint)
            if 'Location' in taint['type']:
                self.assertEqual(taint['ip'], '120.55.192.233')
                self.assertEqual(taint['data'],
                                 "/getAdByClient.action?type=0&version=1&moblieType=GalaxyNexus&imei=351565054929465"
                                 "&appId=BC1DF56")

    def test_parse_dir(self):
        # parse_dir('0897d40edb8b6b585f38ca1a9866bd03cd70a5035cc0ec28f933d702f9a38a03')
        pass

