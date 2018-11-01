#!/usr/bin/env python
"""
Read the logs generated from TaintDroid and extract sensitive PCAPs.
"""
import json
import os
import re
from shutil import copytree, rmtree
from xml.dom.minidom import parseString
import dpkt
from PcapHandler import PcapHandler


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
    if filter_pcap_helper(ip, data, packet):
        return True
    return False


def filter_pcap_helper(ip, data, packet):
    # Set the TCP data
    tcp = packet.data

    src_ip = PcapHandler.inet_to_str(packet.src)
    dst_ip = PcapHandler.inet_to_str(packet.dst)
    # sport = packet.data.sport
    # dport = packet.data.dport

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


def parse_exerciser_log(log_file):
    """
    Parse UIExerciser_FlowIntent_FP_PY.log and get the pkg name.
    :param log_file:
    :return:
    """
    if os.path.exists(log_file):
        with open(log_file) as lines:
            for line in lines:
                if 'pkg:' in line:
                    return line.split('pkg:')[1].replace('\n', '')


def clean_folder(work_dir: str, tsrc: str = 'Location') -> None:
    """
    Filter the Activities that do not contain tsrc taint or meaningful UI.
    :param work_dir:
    :param tsrc:
    :return:
    """
    filter_keys = ['android', 'com.android.launcher',
                   'com.google.android.gsf.login', 'android.widget.LinearLayout']
    for root, dirs, files in os.walk(work_dir, topdown=False):
        for fn in files:
            if not os.path.exists(os.path.join(root, fn)):
                continue
            if str(fn).endswith('.json'):
                flowintent_log = os.path.join(root, '/UIExerciser_FlowIntent_FP_PY.log')
                if os.path.exists(flowintent_log):
                    pkg = parse_exerciser_log(flowintent_log)
                else:
                    pkg = os.path.basename(root)
                taints = parse_json_log(os.path.join(root, fn), pkg)
                found = False
                for taint in taints:
                    if tsrc in taint['src']:
                        found = True
                if not found:
                    rm_instance_meta(root, fn)

            if str(fn).endswith('xml'):
                """
                Clean the xml (and other relevant data) whose content does not contain any app UI.
                """
                xml_path = os.path.join(root, fn)
                with open(xml_path, 'rb') as f:
                    try:
                        others = []
                        android = False
                        data = f.read()
                        dom = parseString(data)
                        nodes = dom.getElementsByTagName('node')
                        # Iterate over all the uses-permission nodes
                        for node in nodes:
                            # print(node.getAttribute('text'))
                            # print(node.toxml())
                            if node.getAttribute('package') in filter_keys:
                                android = True
                            else:
                                others.append(node.getAttribute('package'))
                        if android and len(others) == 0:
                            rm_instance_meta(root, fn)
                    except Exception as e:
                        print(xml_path + ", " + str(e))


def rm_instance_meta(root, fn):
    filename, file_extension = os.path.splitext(fn)
    if '_' in fn:
        if os.path.exists(os.path.join(root, 'first_page.png')):
            os.remove(os.path.join(root, 'first_page.png'))
        if os.path.exists(os.path.join(root, 'first_page.xml')):
            os.remove(os.path.join(root, 'first_page.xml'))
    else:
        if os.path.exists(os.path.join(root, filename + '.png')):
            os.remove(os.path.join(root, filename + '.png'))
        if os.path.exists(os.path.join(root, filename + '.xml')):
            os.remove(os.path.join(root, filename + '.xml'))
    os.remove(os.path.join(root, filename + '.json'))
    os.remove(os.path.join(root, filename + '.pcap'))
    print('del ' + filename)


def organize_dir_based_tsrc(base_dir, out_dir, tsrc='Location', sub_dataset=True):
    """
    Copy the dir to the ground dir based on taint src
    :rtype: object
    :param base_dir:
    :param out_dir:
    :param tsrc:
    :param sub_dataset:
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
                if os.path.exists(dest_dir):
                    rmtree(dest_dir)
                copytree(root, dest_dir)


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
        # Get filtered http requests based on Taintlogs (ip, data)
        flows = PcapHandler.http_requests(pcap_path, filter_func=filter_pcap,
                                          args=[ip, data])
        # Output to pcaps
        for flow in flows:
            pkts = PcapHandler.get_packets(pcap_path)
            PcapHandler.filter_pcap(os.path.dirname(pcap_path), pkts, flow['dest'],
                                    flow['sport'], tag=gen_tag(taint['src']))
        return flows
        # return PcapHandler.match_http_requests(pcap_path, TaintDroidLogProcessor.filter_pcap, [ip, data],
        #                                      gen_pcap=True, tag=TaintDroidLogProcessor.gen_tag(taint['src']))
    except Exception as e:
        print(e)
        return []


def extract_flow_pcap(taint, sub_dir):
    """

    :rtype: object
    :param taint:
    :param sub_dir:
    :return:
    """
    flows = []
    for root, dirs, files in os.walk(sub_dir, topdown=False):
        for filename in files:
            if 'filter' not in filename and re.search('pcap$', filename):
                flows += extract_flow_pcap_helper(taint, os.path.join(root, filename))
    return flows


def parse_logs(sub_dir):
    """
    Parse json log and extract the taint info.
    :param sub_dir:
    :return:
    """
    if os.path.exists(os.path.join(sub_dir, '/UIExerciser_FlowIntent_FP_PY.log')):
        pkg = parse_exerciser_log(sub_dir + '/UIExerciser_FlowIntent_FP_PY.log')
    else:
        pkg = os.path.basename(sub_dir)
    print(pkg)
    taints = []
    for root, dirs, files in os.walk(sub_dir, topdown=False):
        for filename in files:
            if re.search('json$', filename):
                taints += parse_json_log(os.path.join(root, filename), pkg)
    return taints


def parse_dir(work_dir):
    """
    Parse the given dir and for each sub dir (an app info), extract the detected taints from json and the flows based on
     the taints from the pacap.
    :param work_dir:
    :return:
    """
    flows = {}
    for root, dirs, files in os.walk(work_dir, topdown=False):
        for dir_name in dirs:
            print(os.path.join(root, dir_name))
            taints = parse_logs(os.path.join(root, dir_name))
            for taint in taints:
                if 'HTTP' in taint['channel']:
                    print(taint)
                    flows[str(taint)] = extract_flow_pcap(taint, os.path.join(root, dir_name))
    return flows


def write_pcap_txt(dirname, pcap):
    result = os.popen('parse_pcap ' + dirname + '/' + pcap + ' > ' + dirname + '/' + pcap.split('.pcap')[0] + '.txt')
    print(result)


def match_flow(pcap_txt, ip, data, time, dirname, pcap, ips, urls, domains, ip_domain):
    """
    Match network flows in pcap based on ip, data and time.
    :param pcap_txt:
    :param ip:
    :param data:
    :param time:
    :param dirname:
    :param pcap:
    :param ips:
    :param urls:
    :param domains:
    :param ip_domain:
    :return:
    """
    data = data.replace('?', '\?')
    data = data.replace('(', '\(')
    data = data.replace(')', '\)')
    data = data.replace('[', '\[')
    try:
        pcap_txt = open(pcap_txt, 'r')
    except IOError:
        # print dirname + '/' + pcap
        write_pcap_txt(dirname, pcap)
        pcap_txt = open(pcap_txt, 'r')
        # return False
    lines = pcap_txt.readlines()
    flag = False
    # examine all lines in pcap-txt, check whether match
    for i in range(len(lines)):
        # print line
        # try:
        line = lines[i]
        if re.search(data, line):
            flag = True
            ips.add(ip)
            try:
                domain = line.split('//')[1].split('/')[0]
                if domain not in domains:
                    domains.add(domain)
                    if not str(ip) in ip_domain:
                        ip_domain[str(ip)] = [domain]
                    else:
                        ip_domain[str(ip)].append(domain)
                if re.search('http', data):
                    uri = data
                else:
                    try:
                        uri = domain + '/' + data.split('\\')[1]
                    except:
                        uri = domain + data
                urls.add(uri)
            except IndexError:
                print('Data: ' + data)
                print('ERROR URI: ' + line)
                continue
            try:
                # extract port number from pcap_txt
                port = int(lines[i - 1].split(':')[1].split(']')[0])
            except:
                continue
            # print port
            filter_pcap(dirname, pcap, time, port, ip)
    if not flag:
        print(data)
        return False
    else:
        return True


if __name__ == '__main__':
    """
    1. set gen_filtered_taint_pcap = True, clean_folder = False
    2. set gen_filtered_taint_pcap = False
    3. clean_folder = True
    """
    gen_filtered_taint_pcap = False
    dataset = 'Play_win8'
    sub_dataset = True  # Whether contain sub dataset
    base_dir = os.path.join('/mnt/H_DRIVE/COSMOS/output/py/', dataset)
    clean = False

    tsrc = 'Location'
    out_dir = os.path.join('/Documents/FlowIntent/output/ground/', tsrc)
    out_dir = os.path.join(out_dir, dataset)

    if clean:
        clean_folder(out_dir)
        exit(0)

    if gen_filtered_taint_pcap:
        """
        Run this first: derive the filtered pcap based on the taint src
        """
        parse_dir(base_dir)
    else:
        organize_dir_based_tsrc(base_dir, out_dir, tsrc=tsrc, sub_dataset=sub_dataset)
