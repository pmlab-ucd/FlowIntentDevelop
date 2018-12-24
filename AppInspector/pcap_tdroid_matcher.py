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
from utils import set_logger

logger = set_logger('TaintDroidLogProcessor')


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


def match_pcap_ip_url(rule, real):
    """
    The helper function used in http_trace to match sensitive flows.
    :param rule:
    :param real:
    :return:
    """
    ip = rule[0]
    data = rule[1]
    ip_dst = real[0]
    url = real[1]
    if ip_dst == ip:
        if data in url:
            return True
        else:
            logger.debug('Not matched: ' + ip + ', ' + data + ', ' + url)
            return False
    return False


def parse_taint_json_log(log_file, pkg):
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


def apk_name(sub_dir):
    if os.path.exists(os.path.join(sub_dir, 'UIExerciser_FlowIntent_FP_PY.log')):
        pkg = parse_exerciser_log(sub_dir + '/UIExerciser_FlowIntent_FP_PY.log')
    else:
        pkg = os.path.basename(sub_dir)
    return pkg


def clean_folder(work_dir: str) -> None:
    """
    Further remove the Activities that do not contain any meaningful UIs.
    :param work_dir:
    :return:
    """
    filter_keys = ['android', 'com.android.launcher',
                   'com.google.android.gsf.login', 'android.widget.LinearLayout']
    for root, dirs, files in os.walk(work_dir, topdown=False):
        for fn in files:
            if str(fn).endswith('xml'):
                # Clean the hierarchy xml (and other relevant data) whose content does not contain any app UI.
                xml_path = os.path.join(root, fn)
                try:
                    with open(xml_path, 'rb') as f:
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
    os.remove(os.path.join(root, filename + '_sens_http_flows'))
    os.remove(os.path.join(root, filename + '.pcap'))
    logger.info('Delete ' + filename)


def organize_dir_by_taint(src_dir, to_dir, taint='Location', sub_dataset=True):
    """
    Copy the dir to the destination dir (the dir to label ground truth) based on the taint.
    :param src_dir:
    :param to_dir:
    :param taint: The taint type.
    :param sub_dataset: Whether is a dataset located inside a bigger dataset.
    """
    for root, dirs, files in os.walk(src_dir, topdown=False):
        for filename in files:
            # If the given taint type is identified in flows, means it is a target pkg.
            if filename.endswith('_sens_http_flows.json'):
                file_path = os.path.join(root, filename)
                with open(file_path, 'r') as infile:
                    flows = json.load(infile)
                    for flow in flows:
                        if taint in flow['taint']:
                            dirname = os.path.basename(os.path.dirname(file_path))
                            dest_dir = to_dir
                            if sub_dataset:
                                dataset_name = os.path.basename(os.path.abspath(os.path.join(root, os.pardir)))
                                dest_dir = os.path.join(to_dir, dataset_name)
                            logger.debug('root:', root)
                            logger.debug('dirname:', dirname)
                            dest_dir = os.path.join(dest_dir, dirname)
                            if os.path.exists(dest_dir):
                                rmtree(dest_dir)
                            copytree(root, dest_dir)
                            break


def extract_flow_pcap(target_taints, sub_dir):
    """
    Given a taint record, extract the flow in the pcap file and output the pcap flow.
    :rtype: dict
    :param target_taints:
    :param sub_dir:
    :return: flows:
    """
    filter_funcs = []
    args = []
    for http_taint in target_taints:
        filter_funcs.append(match_pcap_ip_url)
        args.append([http_taint['ip'], http_taint['data'], gen_tag(http_taint['src'])])
    flows = dict()
    for filename in os.listdir(sub_dir):
        if 'filter' not in filename and filename.endswith('.pcap'):
            sub_flows = []
            pcap_path = os.path.join(sub_dir, filename)
            for i in range(tcp_stream_number(pcap_path) + 1):
                flow = http_trace(pcap_path, i, matching_funcs=filter_funcs, args=args)
                if flow is not None:
                    sub_flows.append(flow)
            if len(sub_flows) != 0:
                flows[os.path.splitext(filename)[0]] = sub_flows
    return flows


def parse_logs(sub_dir):
    """
    Parse json log and extract the taint info.
    :param sub_dir:
    :return:
    """
    pkg = apk_name(sub_dir)
    logger.info(pkg)
    taints = []
    for root, dirs, files in os.walk(sub_dir, topdown=False):
        for filename in files:
            if filename.endswith('.json'):
                taints += parse_taint_json_log(os.path.join(root, filename), pkg)
    return taints, pkg


def http_taints(taints):
    target_taints = []
    for taint in taints:
        if 'HTTP' in taint['channel']:
            logger.debug(taint)
            ip = taint['dst']
            if 'data=' in taint['message']:
                data = taint['message'].split('data=')[1]
            elif 'data' in taint['message']:
                data = taint['message'].split('data')[1]
            else:
                logger.warn('Cannot extract content from the taint message!')
                continue
            data = data.replace('[', '').replace(']', '')
            data = data.replace('GET ', '') if 'GET ' in data else data
            data = data.replace('POST ', '') if 'POST ' in data else data
            data = data.replace(' ', '')
            target_taints.append({'ip': ip, 'data': data, 'type': str(taint), 'src': taint['src']})
    return target_taints


def parse_dir(work_dir):
    """
    Parse the given dir and for each sub dir (an app's data), extract the detected taints from json, then use the taints
     to match the flows in the pcap.
    :param work_dir:
    :return:
    """
    for root, dirs, files in os.walk(work_dir, topdown=False):
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            logger.debug(dir_path)
            taints, pkg = parse_logs(dir_path)
            flows = extract_flow_pcap(http_taints(taints), dir_path)
            for pcap_fn, sub_flows in flows.items():
                with open(os.path.join(dir_path, pcap_fn + '_sens_http_flows.json'), 'w', encoding="utf8") as outfile:
                    json.dump(sub_flows, outfile)


def match(base_dir, out_dir, taint_type, dataset, has_sub_dataset=False):
    """
    The main procedure of pcap_tdroid_mather.py.
    :param base_dir: The base dir of input dir.
    :param out_dir:
    :param taint_type:
    :param dataset: The dataset name (sub dir of the base dir).
    :param has_sub_dataset: Whether dataset has sub dir.
    """

    base_dir = os.path.join(base_dir, dataset)
    out_dir = os.path.join(out_dir, taint_type)
    out_dir = os.path.join(out_dir, dataset)

    # Derive the interested flows from pcaps based on the taint src, and output the corresponding jsons.
    parse_dir(base_dir)
    # Copy the dir to the destination dir (the dir for labelling ground truth) based on the taint.
    organize_dir_by_taint(base_dir, out_dir, taint_type, has_sub_dataset)
    # Remove the Activities that do not contain the taint or meaningful UI.
    clean_folder(out_dir)


if __name__ == '__main__':
    match('H:/COSMOS/output/py/', 'H:/FlowIntent/output/ground/', 'Location', 'Play_win8', True)
