import unittest
from AppInspector.pcap_tdroid_matcher import *
from utils import set_logger
import logging
import os
import json
import shutil

log = set_logger('TestPcapTaintDroidMatcher', 'DEBUG')


class TestPcapTaintDroidMatcher(unittest.TestCase):
    def test_parse_logs(self):
        taints, pkg = parse_logs('data/raw/0897d40edb8b6b585f38ca1a9866bd03cd70a5035cc0ec28f933d702f9a38a03')
        self.assertEqual(pkg, 'com.gp.mahjongg')
        self.assertEqual(len(taints), 4)
        for taint in taints:
            log.debug(taint)
            self.assertEqual(taint['process_name'], 'com.gp.mahjongg')
            self.assertEqual(taint['channel'], 'HTTP')

    def test_http_taints(self):
        taints, pkg = parse_logs('data/raw/0897d40edb8b6b585f38ca1a9866bd03cd70a5035cc0ec28f933d702f9a38a03')
        tgt_taints = http_taints(taints)
        self.assertEqual(len(tgt_taints), 4)
        for taint in tgt_taints:
            log.debug(taint)
            if 'Location' in taint['type']:
                self.assertEqual(taint['ip'], '120.55.192.233')
                self.assertEqual(taint['data'],
                                 "/getAdByClient.action?type=0&version=1&moblieType=GalaxyNexus&imei=351565054929465"
                                 "&appId=BC1DF56")

    def test_extract_flow_pcap(self):
        logger.setLevel(logging.INFO)
        sub_dir = 'data/raw/0897d40edb8b6b585f38ca1a9866bd03cd70a5035cc0ec28f933d702f9a38a03'
        taints, pkg = parse_logs(sub_dir)
        tgt_taints = http_taints(taints)
        flows = extract_flow_pcap(tgt_taints, sub_dir)
        self.assertEqual(len(flows), 1)
        for pcap_file, sub_flows in flows.items():
            self.assertEqual(len(sub_flows), 3)
            self.assertEqual(pcap_file, 'com.gp.mahjongg0710-03-25-16')
            for flow in sub_flows:
                self.assertTrue('IMEI' in flow['taint'])
                log.debug('Flow: ' + str(flow))
                if 'Location' in flow['taint']:
                    self.assertTrue('location' in flow['url'])

    def test_parse_dir(self):
        target_json = "data/raw/0897d40edb8b6b585f38ca1a9866bd03cd70a5035cc0ec28f933d702f9a38a03/" \
                      "com.gp.mahjongg0710-03-25-16_sens_http_flows.json"
        if os.path.exists(target_json):
            os.remove(target_json)
        parse_dir('data')
        self.assertTrue(os.path.exists(target_json))
        with open(target_json, 'r') as infile:
            flows = json.load(infile)
        self.assertEqual(len(flows), 3)
        for flow in flows:
            self.assertTrue('IMEI' in flow['taint'])
            log.debug('Flow: ' + str(flow))
            if 'Location' in flow['taint']:
                self.assertTrue('location' in flow['url'])

    def test_organize_dir_by_taint(self):
        out_base_dir = 'data/ground/'
        if os.path.exists('data/ground'):
            shutil.rmtree(out_base_dir)
        dataset = 'raw'
        base_dir = os.path.join('data', dataset)

        taint_type = 'Location'
        out_dir = os.path.join(out_base_dir, taint_type)
        out_dir = os.path.join(out_dir, dataset)

        organize_dir_by_taint(base_dir, out_dir, taint_type, False)
        out_dir = 'data/ground/Location/raw/0897d40edb8b6b585f38ca1a9866bd03cd70a5035cc0ec28f933d702f9a38a03'
        target_json = os.path.join(out_dir, 'com.gp.mahjongg0710-03-25-16_sens_http_flows.json')
        self.assertTrue(os.path.exists(target_json))
        with open(target_json, 'r') as infile:
            flows = json.load(infile)
        self.assertEqual(len(flows), 3)
        for flow in flows:
            self.assertTrue('IMEI' in flow['taint'])
            log.debug('Flow: ' + str(flow))
            if 'Location' in flow['taint']:
                self.assertTrue('location' in flow['url'])
        shutil.rmtree(out_base_dir)
