#!/usr/bin/env python
"""
Read the logs generated by TaintDroid and extract the sensitive flows in the PCAPs.
If the sensitive flows are identified of the app, the app's data would be moved to the target directory.

The sensitive flows are located through matching IP and data written inside the TaintDroid's logs.
"""
import json
from shutil import copytree, rmtree
from xml.dom.minidom import parseString
from pcap_processor import *
from utils import Utilities

logger = Utilities.set_logger('TaintDroidLogProcessor')


def gen_tag(src):
    """
    Generate a str specifying what kind of taint has been reported.
    :param src:
    :return:
    """
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
    Filter pcap based on TaintLog: ip and data.
    It is a helper function used as a argument in the main filtering process.
    :param args: including ip and data.
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
    """
    The implementation of filtering pcap based on ip and data.
    :param ip:
    :param data:
    :param packet:
    :return:
    """
    # Set the TCP data
    tcp = packet.data

    src_ip = inet_to_str(packet.src)
    dst_ip = inet_to_str(packet.dst)
    # sport = packet.data.sport
    # dport = packet.data.dport

    if src_ip == ip or dst_ip == ip:
        logger.debug('Found: ' + dst_ip)
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
                logger.warn('Not matched: ' + ip + ', ' + data + ', ' + request.uri)
                return False
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            return False
    return False


def parse_json_log(log_file, pkg):
    """
    Parse the TaintDroid logs (jsons) and return a tainted record.
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
        logger.warn(str(e))
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
    Further remove the Activities that do not contain tsrc taint or meaningful UI.
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
                # Clean the xml (and other relevant data) whose content does not contain any app UI.
                xml_path = os.path.join(root, fn)
                with open(xml_path, 'rb') as f:
                    try:
                        others = []
                        android = False
                        data = f.read()
                        dom = parseString(data)
                        nodes = dom.getElementsByTagName('node')
                        # Iterate over all the uses-permission nodes.
                        for node in nodes:
                            logger.debug(node.getAttribute('text'))
                            logger.debug(node.toxml())
                            if node.getAttribute('package') in filter_keys:
                                android = True
                            else:
                                others.append(node.getAttribute('package'))
                        if android and len(others) == 0:
                            rm_instance_meta(root, fn)
                    except Exception as e:
                        logger.warn('Error while handling ' + xml_path + ", " + str(e))


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
    logger.info('del ' + filename)


def organize_dir_by_taint(src_dir, to_dir, taint='Location', sub_dataset=True):
    """
    Copy the dir to the destination dir (the dir for labelling ground truth) based on the taint.
    :param src_dir:
    :param to_dir:
    :param taint: The taint type.
    :param sub_dataset: Whether is a dataset located inside a bigger dataset.
    """
    for root, dirs, files in os.walk(src_dir, topdown=False):
        for filename in files:
            # If keyword "filter" and founded taint src in filename, means it is a target pkg.
            if 'filter' in filename and taint in filename:
                dirname = os.path.basename(os.path.dirname(os.path.join(root, filename)))
                dest_dir = to_dir
                if sub_dataset:
                    dataset_name = os.path.basename(os.path.abspath(os.path.join(root, os.pardir)))
                    dest_dir = os.path.join(to_dir, dataset_name)
                logger.info('root:', root)
                logger.info('dirname:', dirname)
                dest_dir = os.path.join(dest_dir, dirname)
                if os.path.exists(dest_dir):
                    rmtree(dest_dir)
                copytree(root, dest_dir)


def extract_flow_pcap_helper(taint, pcap_path):
    """
    The helper of extract_flow_pcap.
    Given a taint record, extract the flow in the pcap file and output the pcap flow.
    :param taint:
    :param pcap_path:
    :return:
    """
    ip = taint['dst']
    if 'data=' in taint['message']:
        data = taint['message'].split('data=')[1]
    elif 'data' in taint['message']:
        data = taint['message'].split('data')[1]
    else:
        raise Exception('Cannot extract data from taint message')
    try:
        # Get filtered http requests based on the TaintDroid logs (ip, data).
        flows = http_requests(pcap_path, filter_func=filter_pcap,
                              args=[ip, data])
        # Output to pcaps.
        for flow in flows:
            pkts = get_packets(pcap_path)
            filter_pcap(os.path.dirname(pcap_path), pkts, flow['dest'],
                        flow['sport'], tag=gen_tag(taint['src']))
        return flows
        # return PcapHandler.match_http_requests(pcap_path, TaintDroidLogProcessor.filter_pcap, [ip, data],
        #                                      gen_pcap=True, tag=TaintDroidLogProcessor.gen_tag(taint['src']))
    except Exception as exception:
        logger.info(str(exception))
        return []


def extract_flow_pcap(taint, sub_dir):
    """
    Given a taint record, extract the flow in the pcap file and output the pcap flow.
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
    if os.path.exists(os.path.join(sub_dir, 'UIExerciser_FlowIntent_FP_PY.log')):
        pkg = parse_exerciser_log(sub_dir + '/UIExerciser_FlowIntent_FP_PY.log')
    else:
        pkg = os.path.basename(sub_dir)
    logger.info(pkg)
    taints = []
    for root, dirs, files in os.walk(sub_dir, topdown=False):
        for filename in files:
            if re.search('json$', filename):
                taints += parse_json_log(os.path.join(root, filename), pkg)
    return taints


def parse_dir(work_dir):
    """
    Parse the given dir and for each sub dir (an app's data), extract the detected taints from json and the flows based
    on the taints from the pcap.
    :param work_dir:
    :return:
    """
    flows = {}
    for root, dirs, files in os.walk(work_dir, topdown=False):
        for dir_name in dirs:
            logger.info(os.path.join(root, dir_name))
            taints = parse_logs(os.path.join(root, dir_name))
            for taint in taints:
                if 'HTTP' in taint['channel']:
                    logger.info(taint)
                    flows[str(taint)] = extract_flow_pcap(taint, os.path.join(root, dir_name))
    return flows


def write_pcap_txt(dirname, pcap):
    """
    TODO
    :param dirname:
    :param pcap:
    :return:
    """
    result = os.popen('parse_pcap ' + dirname + '/' + pcap + ' > ' + dirname + '/' + pcap.split('.pcap')[0] + '.txt')
    logger.info(result)


def match_flow(pcap_txt, ip, data, time, dirname, pcap, ips, urls, domains, ip_domain):
    """
    TODO
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
        logger.warn(dirname + '/' + pcap)
        write_pcap_txt(dirname, pcap)
        pcap_txt = open(pcap_txt, 'r')
        # return False
    lines = pcap_txt.readlines()
    flag = False
    # Examine all lines in pcap-txt, check whether match
    for i in range(len(lines)):
        line = lines[i]
        logger.debug(str(line))
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
                    except Exception as e:
                        uri = domain + data
                        logger.debug(e)
                urls.add(uri)
            except IndexError:
                print('Data: ' + data)
                print('ERROR URI: ' + line)
                continue
            try:
                # Extract port number from pcap_txt.
                port = int(lines[i - 1].split(':')[1].split(']')[0])
            except Exception as e:
                logger.warn(e)
                continue
            logger.debug(port)
            filter_pcap(dirname, pcap, time, port, ip)
    if not flag:
        logger.info(data)
        return False
    else:
        return True


if __name__ == '__main__':
    dataset = 'Play_win8'
    has_sub_dataset = True  # Whether contain sub dataset.
    base_dir = os.path.join('/mnt/H_DRIVE/COSMOS/output/py/', dataset)

    taint_type = 'Location'
    out_dir = os.path.join('/Documents/FlowIntent/output/ground/', taint_type)
    out_dir = os.path.join(out_dir, dataset)

    # Derive the filtered pcap based on the taint src.
    parse_dir(base_dir)
    # Copy the dir to the destination dir (the dir for labelling ground truth) based on the taint.
    organize_dir_by_taint(base_dir, out_dir, taint_type, has_sub_dataset)
    # Remove the Activities that do not contain the taint or meaningful UI.
    clean_folder(out_dir)
