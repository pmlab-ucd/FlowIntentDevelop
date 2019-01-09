#!/usr/bin/env python
"""
Read the logs generated by TaintDroid and extract the sensitive flows in the PCAPs.
If the sensitive flows are identified of the app, the app's data would be moved to the target directory.

The sensitive flows are located through matching IP and data written inside the TaintDroid's logs.
"""
from shutil import copytree, rmtree
from xml.dom.minidom import parseString
from pcap_processor import *
from utils import set_logger
from argparse import ArgumentParser
from multiprocessing import Manager, Pool

logger = set_logger('TaintDroidLogProcessor', 'INFO')


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
        tag += 'Microphone_'
    if 'accelerometer' in src:
        tag += 'Accelerometer_'
    if 'camera' in src:
        tag += 'Camera'
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


def skip_by_taint_type(taint, taint_type):
    if taint_type is not None:
        found = False
        for src in taint['src']:
            if taint_type in src or src in taint_type:
                found = True
                break
    else:
        found = True
    return not found


def parse_taint_json_log(log_file, pkg, taint_type=None):
    """
    Parse the TaintDroid logs (jsons) and return a list of recorded taints.
    :param log_file:
    :param pkg:
    :param taint_type:
    :return:
    """
    res = []
    try:
        with open(log_file, 'r', encoding="utf8", errors='ignore') as data_file:
            taints = json.load(data_file)
            for taint in taints:
                if taint['process_name'] in pkg:
                    if skip_by_taint_type(taint, taint_type):
                        continue
                    res.append(taint)
    except Exception as e:
        logger.warn(str(e))
    return res


def parse_taint_old_log(log_file, pkg, taint_type=None):
    """
    Parse the TaintDroid logs (old version, .log) and return a list of recorded taints.
    :param log_file:
    :param pkg:
    :param taint_type:
    :return:
    """
    taints = []
    try:
        file = open(log_file, 'r', errors='ignore')  # open TaintDroid report
        lines = file.readlines()
        for line in lines:
            if pkg in line and 'SSL' not in line:
                taint = dict()
                line = line.split(', ')
                srcs = []
                for i in range(2, len(line) - 3):
                    srcs.append(line[i])
                taint['src'] = srcs
                if skip_by_taint_type(taint, taint_type):
                    continue
                taint['dst'] = line[1]
                taint['message'] = 'data=' + line[len(line) - 2].split(' HTTP')[0]
                taint['channel'] = 'HTTP'
                taints.append(taint)
    except UnicodeDecodeError as e:
        logger.warn('Error in decoding ' + log_file)
        logger.warn(e)
    return taints


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
            data = data.split('HTTP')[0]
            data = data.replace('[', '').replace(']', '')
            data = data.replace('GET ', '') if 'GET ' in data else data
            data = data.replace('POST ', '') if 'POST ' in data else data
            data = data.replace(' ', '')
            target_taints.append({'ip': ip, 'data': data, 'type': str(taint), 'src': taint['src']})
    return target_taints


def parse_exerciser_log(log_file):
    """
    Parse UIExerciser_FlowIntent_FP_PY.log and get the pkg name.
    :param log_file:
    :return:
    """
    if os.path.exists(log_file):
        with open(log_file, encoding="utf8", errors='ignore') as lines:
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
                    with open(xml_path, 'rb', encoding="utf8", errors='ignore') as f:
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
                with open(file_path, 'r', encoding="utf8", errors='ignore') as infile:
                    flows = json.load(infile)
                    for flow in flows:
                        if taint in flow['taint']:
                            dirname = os.path.basename(os.path.dirname(file_path))
                            dest_dir = to_dir
                            if sub_dataset:
                                dataset_name = os.path.basename(os.path.abspath(os.path.join(root, os.pardir)))
                                dest_dir = os.path.join(to_dir, dataset_name)
                            logger.debug('root: ' + root)
                            logger.debug('dirname:' + dirname)
                            dest_dir = os.path.join(dest_dir, dirname)
                            if os.path.exists(dest_dir):
                                rmtree(dest_dir)
                            copytree(root, dest_dir)
                            break


def extract_flow_pcap(sub_dir, target_taints=None):
    """
    Given a taint record, extract the flow in the pcap file and output the pcap flow.
    :param sub_dir:
    :param target_taints:
    """
    flows = []
    if target_taints is not None:
        filter_funcs = []
        args = []
        for http_taint in target_taints:
            filter_funcs.append(match_pcap_ip_url)
            args.append([http_taint['ip'], http_taint['data'], gen_tag(http_taint['src'])])
        flows2jsons(sub_dir, flows, filter_funcs=filter_funcs, args=args, fn_filter='filter')
        logger.debug(str(len(flows)) + ' ' + str(flows))
        if len(flows) == 0:
            logger.warn(sub_dir + ' does not contain any interested taint!')
    return flows


def parse_logs(sub_dir, taint=None):
    """
    Parse json/log and extract the taint info.
    :param sub_dir:
    :param taint:
    :return:
    """
    pkg = apk_name(sub_dir)
    logger.info(pkg + ", " + sub_dir)
    taints = []
    for root, dirs, files in os.walk(sub_dir, topdown=False):
        for filename in files:
            file = os.path.join(root, filename)
            if filename.endswith('.json') and 'sens_' not in filename:
                taints += parse_taint_json_log(file, pkg, taint_type=taint)
            elif filename.endswith(
                    '.log') and 'UiDroid-Console' not in filename and 'UIExerciser_FlowIntent_FP_PY' not in filename:
                taints += parse_taint_old_log(file, pkg, taint_type=taint)
    return taints, pkg


def parse_dir(work_dir, taint=None, visited=None):
    """
    Parse the given dir and for each sub dir (an app's data), extract the detected taints from json, then use the taints
     to match the flows in the pcap.
    :param work_dir:
    :param taint:
    :param visited:
    :return:
    """
    for root, dirs, files in os.walk(work_dir, topdown=False):
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            if visited is not None:
                if dir_path in visited:
                    continue
                else:
                    visited[dir_path] = 1
            logger.debug(dir_path)
            taints, pkg = parse_logs(dir_path, taint=taint)
            extract_flow_pcap(dir_path, target_taints=http_taints(taints))


def parse_dir_mp_wrapper(args):
    return parse_dir(*args)


def match(base_dir, out_dir, taint_type, dataset, has_sub_dataset=False, proc_num=4):
    """
    The main procedure of pcap_tdroid_mather.py.
    :param base_dir: The base dir of input dir.
    :param out_dir: The base dir of output dir. It is the folder to put organized (i.e. ordered by taint type) data.
    :param taint_type: The taint type, such as Location, IMEI, etc. See "gen_tag(src)".
    :param dataset: The dataset name (sub dir of the base dir).
    :param has_sub_dataset: Whether dataset has sub dir.
    :param proc_num: The number of processes used in multiprocessing.
    """
    if dataset is not None:
        base_dir = os.path.join(base_dir, dataset)
    if proc_num != 0:
        # Derive the interested flows from pcaps based on the taint src, and output the corresponding jsons.
        visited = Manager().dict()

        p = Pool(proc_num)
        p.map(parse_dir_mp_wrapper, [(base_dir, taint_type, visited)] * proc_num)
        p.close()
    else:
        logger.info('Reorg flag is set, will not generate flow json this time.')

    if out_dir is None:
        logger.debug('No output folder is given, terminate.')
        return
    out_dir = os.path.join(out_dir, taint_type)
    out_dir = os.path.join(out_dir, dataset)
    # Copy the dir to the destination dir (the dir for labelling ground truth) based on the taint.
    organize_dir_by_taint(base_dir, out_dir, taint_type, has_sub_dataset)
    # Remove the Activities that do not contain the taint or meaningful UI.
    clean_folder(out_dir)


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-i", "--indir", dest="in_dir",
                        help="the full path of the base dir of input directory")
    parser.add_argument("-o", "--outdir", dest="out_dir", default=None,
                        help="the full path of the base dir of output directory")
    parser.add_argument("-t", "--taint", dest="taint",
                        help="the taint type, such as Location, IMEI, Address, etc.")
    parser.add_argument("-d", "--dataset", dest="dataset", default=None,
                        help="the dataset name (sub dir of the base dir)")
    parser.add_argument("-s", "--sub", dest="sub_dir", action='store_true', default=False,
                        help="whether dataset has sub dir")
    parser.add_argument("-r", "--reorganize", dest="reorg", action='store_true', default=False,
                        help="only reorganize the data, no need to reparsing the pcap.")
    parser.add_argument("-p", "--proc", dest="proc_num", default=4,
                        help="the number of processes used in multiprocessing")
    parser.add_argument("-l", "--log", dest="log", default='INFO',
                        help="the log level, such as INFO, DEBUG")
    args = parser.parse_args()
    if args.log != 'INFO':
        logger = set_logger('TaintDroidLogProcessor', args.log)
    # Example: pcap_tdroid_matcher.py -i test/data -o test/data/ground/ -t Location -d raw
    proc_num = 0 if args.reorg else args.proc_num
    match(args.in_dir, args.out_dir, args.taint, args.dataset, has_sub_dataset=args.sub_dir, proc_num=proc_num)
