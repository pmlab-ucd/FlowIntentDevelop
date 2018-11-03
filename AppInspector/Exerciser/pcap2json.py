#!/usr/bin/env python
"""
    Convert pcap files into jsons, each trace has a json
    Filter traces based on the given labels
"""
from dpkt.compat import compat_ord
import json
import simplejson
import pandas as pd
import matplotlib.dates as dt
import pylab
import datetime
import csv

from PacpHandler import PcapHandler
from parse_ctu_label import read_csv, csv_filter_http

from scapy.all import *
from scapy.layers.inet import IP, TCP


def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def filter_pcap_helper(ip, port, packet):
    src_ip = PcapHandler.inet_to_str(packet.src)
    dst_ip = PcapHandler.inet_to_str(packet.dst)
    sport = packet.data.sport
    dport = packet.data.dport

    if str(sport) == str(port) or str(dport) == str(port) \
            and src_ip == ip or dst_ip == ip:
        # print 'Found: ' + dst_ip
        return True
    return False


def filter_pcap(args, packet):
    csv_packets = args[0]
    # print 'called'
    for csv_packet in csv_packets:
        if filter_pcap_helper(csv_packet['DstAddr'], csv_packet['Sport'], packet):
            return True
    return False


def filter_flow(args, flow):
    csv_packets = args[0]

    # print 'called'
    for csv_packet in csv_packets:
        dest_ip = csv_packet['DstAddr']
        sport = csv_packet['Sport']
        time = csv_packet['StartTime']
        if str(sport) == str(flow['sport']) and str(flow['dest']) == str(dest_ip):
            # if time == flow['timestamp']:
            # print 'Found: ' + dst_ip
            return True
            # else:
            #   print time, flow['timestamp']

    return False


def pcap2jsons(pcap_dir, out_dir, filter_func=None, *args):
    filtered = []
    for root, dirs, files in os.walk(pcap_dir, topdown=True):
        for name in files:
            # print(os.path.join(root, name))
            if str(name).endswith('.pcap'):
                pcap_path = os.path.join(root, name)
                if '/0/' in pcap_path:
                    label = 0
                elif '/1/' in pcap_path:
                    label = 1
                else:
                    label = 'unknown'
                """Open up a test pcap file and print out the packets"""
                print pcap_path
                filtered += PcapHandler.http_requests(pcap_path, filter_flow=filter_func, args=args)
    print out_dir
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    for flow in filtered:
        timestamp = flow['timestamp'].replace(':', '-')
        timestamp = timestamp.replace('.', '-')
        timestamp = timestamp.replace(' ', '_')
        filename = str(flow['domain'] + '_' + timestamp + '.json').replace(':', '_').replace('/', '_')
        with open(os.path.join(out_dir, filename), 'w') as outfile:
            try:
                json.dump(flow, outfile)
            except UnicodeDecodeError as e:
                print e
    return filtered


def dir2jsons(json_dir):
        jsons = []
        if json_dir is None:
            return jsons
        for root, dirs, files in os.walk(json_dir, topdown=False):
            for filename in files:
                if '201' in filename and re.search('json$', filename):
                    with open(os.path.join(root, filename), "rb") as fin:
                        try:
                            jsons.append(simplejson.load(fin))
                        except Exception as e:
                            pass
                            # Utilities.logger.error(e)
        return jsons

def examin_session(session, ip, port):
    for pkt in session:
        if IP in pkt and TCP in pkt:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            tcp_sport = pkt[TCP].sport
            tcp_dport = pkt[TCP].dport

            if (ip_src == ip or ip_dst == ip) and (
                    tcp_dport == port or tcp_sport == port):
                return True
    return False


def filter_tcp_streams(pcap_path, out_dir, json_dir, gen_streams=False, tag=''):
    """
    Parse json and filter the pcap to generte subpcap
    :param json_dir:
    :param pcap_path:
    :param out_dir:
    :return:
    """
    #pkts = PcapHandler.get_packets(pcap_path)
    if gen_streams:
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)
        pkts = rdpcap(pcap_path)
        jsons = dir2jsons(json_dir)
        print len(jsons)
        for json in jsons:
            if json['src'] != '147.32.84.165' and json['dest'] != '147.32.84.165':
                continue
            print json
            PcapHandler.filter_pcap(out_dir, pkts, json['dest'],
                                    json['sport'], tag=tag)

        """
        streams = PcapHandler.tcp_streams(pcap_path)
        jsons = dir2jsons(json_dir)
        print len(jsons)
        for json in jsons:
            if json['src'] != '147.32.84.165' and json['dest'] != '147.32.84.165':
                continue
            print json
            ip_src = stream['src']
            ip_dest = stream['dest']
            tcp_sport = stream['sport']
            tcp_dport = stream['dport']
            ip = json['dest']
            port = json['sport']
            for stream in streams:
                if (ip_src == ip or ip_dest == ip) and (
                                tcp_dport == port or tcp_sport == port):
                    i  = stream['index']
                    out_pcap = os.path.join(out_dir, ip + '_filtered_' + tag + '_' + str(port) + '.pcap')
                    cmd = 'tshark -r ' + pcap_path + ' -Y "tcp.stream==' + str(i) + '" -w ' + out_pcap
                    print cmd
                    os.system(cmd)
            """
        return





    ts_pks = []
    for root, dirs, files in os.walk(out_dir, topdown=True):
        for name in files:
            # print(os.path.join(root, name))
            if '_ts_' in name and str(name).endswith('.pcap'):
                ts_pcap_path = os.path.join(root, name)
                if os.path.exists(ts_pcap_path):
                    try:
                        pkts = rdpcap(pcap_path)
                        ts_pks.append(pkts)
                    except:
                        continue
                    PcapHandler.duration_pcap(ts_pcap_path)


def durations(base_dir, timestamps, label):
    input_dir = os.path.join(base_dir, label)
    for root, dirs, files in os.walk(input_dir, topdown=True):
        for name in files:
            # print(os.path.join(root, name))
            if str(name).endswith('.pcap'):
                pcap_path = os.path.join(root, name)
                min_val, max_val = PcapHandler.duration_pcap(pcap_path)
                data = dict()
                data['min'] = datetime.datetime.utcfromtimestamp(min_val)
                data['max'] = datetime.datetime.utcfromtimestamp(max_val)
                data['category'] = label
                timestamps.append(data)


def event_duration(base_dir):
    csv_file = os.path.join(base_dir, 'timestamps.csv')

    if not os.path.exists(csv_file):
        timestamps = []
        durations(base_dir, timestamps, 'TCP-CC')
        durations(base_dir, timestamps, 'Ad')
        with open(csv_file, "wb") as file:
            writer = csv.writer(file, delimiter=',')
            writer.writerow(["Category", "Min", "Max"])

            for data in timestamps:
                writer.writerow([data['category'], data['min'], data['max']])

    else:
        df = pd.read_csv(csv_file)

        # map categories to y-values
        cat_dict = dict(zip(pd.unique(df.Category), range(1, len(df.Category) + 1)))

        # map y-values to categories
        val_dict = dict(zip(range(1, len(df.Category) + 1), pd.unique(df.Category)))

        # determing the y-values from categories
        df.Category = df.Category.apply(cat_dict.get)

        df.Min = pd.to_datetime(df.Min).astype(datetime.datetime)
        print df.Min, dt.date2num(df.Min.astype(datetime.datetime))
        df.Max = pd.to_datetime(df.Max).astype(datetime.datetime)
        print dt.date2num(df.Min)

        fig = plt.figure()
        ax = fig.add_subplot(111)
        ax = ax.xaxis_date()
        ax = plt.hlines(df.Category, dt.date2num(df.Min), dt.date2num(df.Max))

        pylab.show()


if __name__ == '__main__':
    '''
    dir = '/mnt/Documents/flows/CTU-13/CTU-13-1/'
    dir_0 = dir + '0/'
    label = 'Ad' #TCP-CC' #SPAM'
    for root, dirs, files in os.walk(dir_0, topdown=True):
        for name in files:
            # print(os.path.join(root, name))
            if str(name).endswith('binetflow.2format'):
                headers, csv_packets = read_csv(os.path.join(dir_0, name),
                                    csv_filter_http, label=label)
                flows = pcap2jsons(dir_0, dir_0 + '/' + label, filter_flow, csv_packets)
                print len(csv_packets), len(flows)

                for csv_packet in csv_packets:
                    print csv_packet['DstAddr'], csv_packet['Sport'], csv_packet['StartTime'], csv_packet['LastTime']
                print '_________________________________'
                for flow in flows:
                    print flow['dest'], flow['sport'], flow['uri']

    '''
    #dir_1 = '/mnt/Documents/flows/FlowIntent/Address'
    #pcap2jsons(dir_1, dir_1)
    label = 'Ad'
    pcap_path = '/mnt/Documents/flows/Event/147-32-84-165/147-32-84-165.pcap'
    #filter_tcp_streams(pcap_path,
     #         '/mnt/Documents/flows/Event/147-32-84-165/' + label, '/mnt/Documents/flows/Event/' + label,
      #                 tag=label, gen_streams=True)
    streams = PcapHandler.tcp_streams(pcap_path, out_dir='/mnt/Documents/flows/Event/147-32-84-165/')
