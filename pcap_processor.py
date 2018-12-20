__author__ = 'hao'

from scapy.layers.inet import IP, TCP
from scapy.all import *
import dpkt
import datetime
import socket
from dpkt.compat import compat_ord

from utils import set_logger

logger = set_logger('pcap_processor')

# import win_inet_pton


"""
The utilities to process pcap files. 
"""


def tcp_streams(pcap_path, out_dir=None):
    """
    Retrieve tcp packets from a pcap and output to a pcap, with the help of tshark.
    :param pcap_path:
    :param out_dir:
    :return:
    """
    amount = os.popen('tshark -r ' + pcap_path + ' -T fields -e tcp.stream | sort -n | tail -1').read()
    streams = []
    logger.debug(amount)
    """
    for i in range(int(amount)):
        stream = dict()
        cmd = 'tshark -r ' + pcap_path + ' -qz follow,tcp,ascii,' + str(i)
        output = os.popen(cmd).readlines()
        for line in output:
            if 'Node 0' in line:
                line = line.replace(': ', '-')

                ip = line.split(':')[0].split('-')[1]
                port = line.split(':')[1].replace('\n', '')
                stream['src'] = ip
                stream['sport'] = port
            if 'Node 1' in line:
                line = line.replace(': ', '-')

                ip = line.split(':')[0].split('-')[1]
                port = line.split(':')[1].replace('\n', '')
                stream['dest'] = ip
                stream['dport'] = port
                stream['index'] = i
                print stream
                streams.append(stream)
    """

    if out_dir is None:
        return
    for i in range(int(amount)):
        out_pcap = os.path.join(out_dir,
                                os.path.basename(pcap_path).replace('.pcap', '') + '_ts_' + str(i) + '.pcap')
        if os.path.exists(out_pcap):
            continue
        cmd = 'tshark -r ' + pcap_path + ' -Y "tcp.stream==' + str(i) + '" -w ' + out_pcap
        logger.info(cmd)
        os.system(cmd)
    return streams


def print_pacp(pcap):
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            logger.debug('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now grab the data within the Ethernet frame (the IP packet)
        ip = eth.data

        # Check for TCP in the transport layer
        if isinstance(ip.data, dpkt.tcp.TCP):
            # Set the TCP data
            tcp = ip.data

            # Now see if we can parse the contents as a HTTP request
            try:
                request = dpkt.http.Request(tcp.data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue

            # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
            do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
            more_fragments = bool(ip.off & dpkt.ip.IP_MF)
            fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

            # Print out the info
            logger.info('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))
            logger.info('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)
            logger.info('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)', inet_to_str(ip.src),
                        inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)
            logger.info('HTTP request: %s\n' % repr(request))


def inet_to_str(inet):
    """
    Convert inet object to a string
    Args:
            inet (inet struct): inet network address
    Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def http_requests_helper(pcap, label='', filter_by_packet_info=None, filter_by_flow_info=None, args=None):
    """
    The implementation of http_requests, which extract the interested http requests from a given pcap.
    :param: pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    :param: label: The supervised learning label of the extracted http requests.
    :param: filter_by_packet_func: filter http requests based on packet info.
    :param: filter_by_flow_info: filter http requests based on flow info.
    :param: args: The args used by filters.
    """
    # For each packet in the pcap process the contents
    flows = []
    examined = []  # There might be some repeated flows, do not know why but we need to filter them.
    for timestamp, buf in pcap:
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except Exception as e:
            logger.debug(str(e))
            continue
        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            # print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now grab the data within the Ethernet frame (the IP packet)
        packet = eth.data

        # Check for TCP in the transport layer
        if isinstance(packet.data, dpkt.tcp.TCP):
            # Set the TCP data
            tcp = packet.data
            # Now see if we can parse the contents as a HTTP request
            try:
                request = dpkt.http.Request(tcp.data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue

            if filter_by_packet_info is not None and not filter_by_packet_info(args, packet):
                continue
            flow = dict()
            # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
            do_not_fragment = bool(packet.off & dpkt.ip.IP_DF)
            more_fragments = bool(packet.off & dpkt.ip.IP_MF)
            fragment_offset = packet.off & dpkt.ip.IP_OFFMASK

            # Print out the info
            timestamp = str(datetime.datetime.utcfromtimestamp(timestamp))

            logger.debug('Timestamp: ', timestamp)
            logger.debug('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)
            logger.debug('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' %
                         (inet_to_str(packet.src), inet_to_str(packet.dst), packet.len, packet.ttl, do_not_fragment,
                          more_fragments, fragment_offset))
            logger.debug('HTTP request: %s\n' % repr(request))
            logger.debug(tcp.sport + tcp.dport)
            flow['label'] = label
            flow['post_body'] = request.body.decode("ISO-8859-1")
            try:
                flow['domain'] = request.headers['host']
            except Exception as e:
                flow['domain'] = str(inet_to_str(packet.dst))
                logger.debug(str(e))
            flow['uri'] = request.uri
            flow['headers'] = request.headers
            flow['platform'] = 'unknown'
            flow['referrer'] = 'unknown'
            flow['src'] = inet_to_str(packet.src)
            flow['sport'] = tcp.sport
            flow['dest'] = inet_to_str(packet.dst)
            flow['dport'] = tcp.dport
            flow['request'] = repr(request)
            flow['timestamp'] = timestamp
            logger.debug(repr(flow))
            identifier = flow['dest'] + str(flow['sport']) + flow['uri']
            if filter_by_flow_info is not None and filter_by_flow_info(args, flow):
                continue

            if identifier not in examined:
                flows.append(flow)
                examined.append(identifier)

            # Check for Header spanning crossing TCP segments
            if not tcp.data.endswith(b'\r\n'):
                logger.debug('\nHEADER TRUNCATED! Reassemble TCP segments!\n')
                pass
    return flows


def http_requests(pcap_path, label='', filter_func=None, filter_flow=None, args=None):
    """
    Extract http requests from the pcap, based on the given filter function.
    :param pcap_path:
    :param label:
    :param filter_func:
    :param filter_flow:
    :param args:
    :return:
    """
    with open(pcap_path, 'rb') as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except Exception as e:
            logger.warn(str(e))
            return None
        # flows = print_http_requests(pcap, label, filter_func, args)
        return http_requests_helper(pcap, label, filter_by_packet_info=filter_func,
                                    filter_by_flow_info=filter_flow, args=args)


def duration(pkts):
    timestamps = []
    sessions = pkts.sessions()
    for session in sessions:
        print(session)
        for packet in sessions[session]:
            timestamps.append(packet.time)
    return min(timestamps), max(timestamps)


def duration_pcap(pcap_path):
    pkts = rdpcap(pcap_path)
    return duration(pkts)


def filter_pcap_tshark(dirname, pcap_path, ip, port, tag=''):
    """
    Filter pcap using tshark.
    Notice this does not include HTTP responses.
    :param dirname:
    :param pcap_path:
    :param ip:
    :param port:
    :param tag:
    :return:
    """
    ip = str(ip)
    port = str(port)
    output_path = os.path.join(dirname, ip + '_filtered_' + tag + '_' + str(port) + '.pcap')
    if os.path.exists(output_path):
        return
    os.system(
        'tshark -r ' + pcap_path + ' -Y "ip.addr==' + ip + ' and tcp.srcport==' + port + '" -w ' + output_path)


def filter_pcap(dirname, pkts, ip, port, tag=''):
    """
    Given a set of packets, find the packets matching the given condition such as ip and port,
    and then write the selected packets into a pcap.
    Timestamp is not accurate.
    :param dirname: The output dir
    :param pkts: A set of packets.
    :param ip: The filter condition -- ip.
    :param port: The filter condition -- port.
    :param tag: The tag used in the filename of the output pcap.
    :return: None.
    """
    ip = str(ip)
    port = str(port)
    output_path = os.path.join(dirname, ip + '_filtered_' + tag + '_' + str(port) + '.pcap')
    if os.path.exists(output_path):
        return

    filtered = []  # To store the selected packets.
    for pkt in pkts:
        # If it is a not TCP, must not be a HTTP packet.
        if TCP not in pkt:
            return

        logger.debug(pkt[TCP].sport)
        # If the src port or the dest port matches and if the src ip or the dest ip matches.
        if str(pkt[TCP].sport) == str(port) or str(pkt[TCP].dport) == str(port) \
                and pkt[IP].dst == ip or pkt[IP].src == ip:
            logger.debug('Found: ' + pkt[IP].dst)
            filtered.append(pkt)
    # Write to a new pcap.
    wrpcap(output_path, filtered)


def filter_pcap_by_ip(dirname, pkts, ip):
    ip = str(ip)
    output_path = os.path.join(dirname, ip + '.pcap')
    if os.path.exists(output_path):
        return
    filtered = []
    for pkt in pkts:
        if TCP in pkt and (pkt[IP].dst == ip or pkt[IP].src == ip):
                logger.debug('Found: ' + pkt[IP].dst)
                filtered.append(pkt)
    wrpcap(output_path, filtered)


if __name__ == '__main__':
    input_pcap_path = '/mnt/Documents/FlowIntent/output/test/2421536307fd9a885cc66c58419cea2e307620dfb67ab96f11aa33380da14c93' \
                      '/com.mogo.katongllk0710-08-27-45.pcap'
    tcp_streams(input_pcap_path)

    """
    p = rdpcap(pcap_path)
    sessions = p.sessions()
    for session in sessions:
        http_payload = ""
        print sessions[session]
        for packet in sessions[session]:
            try:
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    http_payload += str(packet[TCP].payload)
                print packet[TCP].sport
                break
            except:
                pass

    """
