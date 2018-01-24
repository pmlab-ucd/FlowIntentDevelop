#!/usr/bin/env python
import json
import os
import re
from AppInspector.PacpHandler import PcapHandler
import dpkt
from shutil import copytree

"""
Process the generated logs from TaintDroid after the execution of the apps
"""


class TaintDroidLogProcessor():
    @staticmethod
    def parse_exerciser_log(log_file):
        try:
            with open(log_file) as lines:
                for line in lines:
                    if 'pkg:' in line:
                        return line.split('pkg:')[1].replace('\n', '')
        except:
            return

    @staticmethod
    def parse_json_log(log_file, pkg):
        """
        Parse the TaindDroid logs (jsons) and return a tainted record
        :param log_file:
        :param pkg:
        :return:
        """
        res = []
        try:
            with open(log_file) as data_file:
                taints = json.load(data_file)
                for taint in taints:
                    if taint['process_name'] in pkg:
                        res.append(taint)
        except Exception as e:
            print(e)
        return res

    @staticmethod
    def filter_pcap_helper(ip, data, packet):
        # Set the TCP data
        tcp = packet.data

        src_ip = PcapHandler.inet_to_str(packet.src)
        dst_ip = PcapHandler.inet_to_str(packet.dst)
        #sport = packet.data.sport
        #dport = packet.data.dport

        if src_ip == ip or dst_ip == ip:
            # print 'Found: ' + dst_ip
            try:
                request = dpkt.http.Request(tcp.data)
                data = str(data).replace('[', '')
                data = data.replace(']', '')

                if 'GET ' in data:
                    data = data.replace('GET ', '')
                elif 'POST ' in data:
                    data = data.replace('POST ', '')
                data = data.replace(' ', '')
                if data in request.uri:
                    return True
                else:
                    # print 'Not matched: ' + ip + ', ' + data + ', ' + request.uri
                    return False
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                return False
        return False

    @staticmethod
    def filter_pcap(args, packet):
        """
        Filter pcap based on TaintLog: ip and data
        :param args:
        :param packet:
        :return:
        """
        ip = args[0]
        data = args[1]
        # print 'called'
        if TaintDroidLogProcessor.filter_pcap_helper(ip, data, packet):
                return True
        return False

    @staticmethod
    def gen_tag(src):
        src = str(src)
        tag = ''
        if 'Location' in src:
            tag += 'Location_'
        if 'IMEI' in src:
            tag += 'IMEI_'
        if 'ICCID' in src:
            tag += 'ICCID_'
        if 'ContactsProvider' in src:
            tag += 'Address_'
        if 'Microphone Input' in src:
            tag += 'microphone_'
        if 'accelerometer' in src:
            tag += 'accelerometer_'
        if 'camera' in src:
            tag += 'camera'
        if tag.endswith('_'):
            tag = tag[:-1]
        return tag

    @staticmethod
    def extract_flow_pcap_helper(taint, pcap_path):
        """
        Given a taint record, extract the flow in the pcap file and output the pcap flow.
        :param taint:
        :return:
        """
        ip = taint['dst']
        if 'data=' in taint['message']:
            data = taint['message'].split('data=')[1]
        elif 'data' in taint['message']:
            data = taint['message'].split('data')[1]
        else:
            raise Exception
        try:
        #if True:
            # Get filtered http requests based on Taintlogs (ip, data)
            flows = PcapHandler.http_requests(pcap_path, filter_func=TaintDroidLogProcessor.filter_pcap, args=[ip, data])
            # Output to pcaps
            for flow in flows:
                pkts = PcapHandler.get_packets(pcap_path)
                PcapHandler.filter_pcap(os.path.dirname(pcap_path), pkts, flow['dest'],
                                        flow['sport'], tag=TaintDroidLogProcessor.gen_tag(taint['src']))
            return flows
            #return PcapHandler.match_http_requests(pcap_path, TaintDroidLogProcessor.filter_pcap, [ip, data],
             #                                      gen_pcap=True, tag=TaintDroidLogProcessor.gen_tag(taint['src']))
        except Exception as e:
            print(e)
            return []

    @staticmethod
    def extract_flow_pcap(taint, sub_dir):
        flows = []
        for root, dirs, files in os.walk(sub_dir, topdown=False):
            for filename in files:
                if 'filter' not in filename and re.search('pcap$', filename):
                    flows += TaintDroidLogProcessor.extract_flow_pcap_helper(taint, os.path.join(root, filename))
        return flows

    @staticmethod
    def paser_logs(sub_dir):
        if os.path.exists(os.path.join(sub_dir, '/UIExerciser_FlowIntent_FP_PY.log')):
            pkg = TaintDroidLogProcessor.parse_exerciser_log(sub_dir + '/UIExerciser_FlowIntent_FP_PY.log')
        else:
            pkg = os.path.basename(sub_dir)
        print(pkg)
        taints = []
        for root, dirs, files in os.walk(sub_dir, topdown=False):
            for filename in files:
                if re.search('json$', filename):
                    taints += TaintDroidLogProcessor.parse_json_log(os.path.join(root, filename), pkg)
        return taints

    @staticmethod
    def parse_dir(out_dir):
        flows = {}
        for root, dirs, files in os.walk(out_dir, topdown=False):
            for dir in dirs:
                print(os.path.join(root, dir))
                taints = TaintDroidLogProcessor.paser_logs(os.path.join(root, dir))
                for taint in taints:
                        if 'HTTP' in taint['channel']:
                            print(taint)
                            flows[str(taint)] = TaintDroidLogProcessor.extract_flow_pcap(taint, os.path.join(root, dir))
        return flows

    @staticmethod
    def organize_dir_based_tsrc(base_dir, out_dir, tsrc='Location', sub_dataset=True):
        """
        Copy the dir to the ground dir based on taint src
        :return:
        """
        for root, dirs, files in os.walk(base_dir, topdown=False):
            for filename in files:
                if re.search('filter', filename) and tsrc in filename:
                    dirname = os.path.basename(os.path.dirname(os.path.join(root, filename)))
                    dest_dir = out_dir
                    if sub_dataset:
                        dataset_name = os.path.basename(os.path.abspath(os.path.join(root, os.pardir)))
                        dest_dir = os.path.join(out_dir, dataset_name)
                    print('root:', root)
                    print('dirname:', dirname)
                    dest_dir = os.path.join(dest_dir, dirname)
                    if not os.path.exists(dest_dir):
                        copytree(root, dest_dir)

    @staticmethod
    def clean_folder(out_dir):
        """
        Clean the activity that does not contain tsrc taint
        :return:
        """
        for root, dirs, files in os.walk(out_dir, tsrc = 'Location', topdown=False):
            for fn in files:
                if str(fn).endswith('.json'):
                    flowintent_log = os.path.join(root, '/UIExerciser_FlowIntent_FP_PY.log')
                    if os.path.exists(flowintent_log):
                        pkg = TaintDroidLogProcessor.parse_exerciser_log(flowintent_log)
                    else:
                        pkg = os.path.basename(root)
                    taints = TaintDroidLogProcessor.parse_json_log(os.path.join(root, fn), pkg)
                    found = False;
                    for taint in taints:
                        if tsrc in taint['src']:
                           found = True
                    if found:
                        os.remove(os.path.join(root, fn))
                        filename, file_extension = os.path.splitext(fn)
                        if '_' in fn:
                            try:
                                os.remove(os.path.join(root, 'first_page.png'))
                            except:
                                print('cannot find ' + os.path.join(root, 'first_page.png'))
                            try:
                                os.remove(os.path.join(root, 'first_page.xml'))
                            except:
                                print('cannot find ' + os.path.join(root, 'first_page.png'))
                        else:
                            os.remove(os.path.join(root, filename + '.png'))
                            os.remove(os.path.join(root, filename + '.xml'))
                        os.remove(os.path.join(root, filename + '.pcap'))
                        print('del ' + filename)


if __name__ == '__main__':
    """
    1. set gen_filtered_taint_pcap = True, clean_folder = False
    2. set gen_filtered_taint_pcap = False
    3. clean_folder = True
    """
    gen_filtered_taint_pcap = False
    dataset = 'Play_win8'
    sub_dataset = True # Whether contain sub dataset
    base_dir = os.path.join('/mnt/H_DRIVE/COSMOS/output/py/', dataset)
    clean_folder = True

    tsrc = 'Location'
    out_dir = os.path.join('/mnt/H_DRIVE/FlowIntent/output/ground/', tsrc)
    out_dir = os.path.join(out_dir, dataset)

    if clean_folder:
        TaintDroidLogProcessor.clean_folder(out_dir)
        exit(0)

    if gen_filtered_taint_pcap:
        """
        Run this first: derive the filtered pcap based on the taint src
        """
        taints = TaintDroidLogProcessor.parse_dir(base_dir)
        for taint in taints:
            print(taint, taints[taint])
    else:
        TaintDroidLogProcessor.organize_dir_based_tsrc(base_dir, out_dir, tsrc=tsrc, sub_dataset=sub_dataset)