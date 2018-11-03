import csv

from scapy.all import *
from PacpHandler import PcapHandler
import networkx as nx
import matplotlib.pyplot as plt
import json
from networkx_viewer import Viewer


def csv_filter_http(label='-TCP-CC', item=None, items=None):
    if item['Proto'] != 'tcp' or not label in item['Label']:
        return
    items.append(item)
    #print item


def read_csv(csv_path, csv_filter=None, label='-TCP-CC'):
    f = open(csv_path)
    reader = csv.reader(f)
    headers = next(reader, None)

    items = []
    for row in reader:
        item = dict()
        for h, v in zip(headers, row):
            item[h] = v
            # columns[h].append(v)
        if csv_filter is not None:
            csv_filter(label=label, item=item, items=items)
        else:
            items.append(item)
    # print(columns)
    print(len(items))

    columns = {}
    for h in headers:
        columns[h] = []

    for row in reader:
        for h, v in zip(headers, row):
            columns[h].append(v)
    # print(len(columns))

    headers = []
    for h in columns:
        if len(str(h)) == 0:
            continue
        headers.append(h)

    return headers, items

def mapping_c2_attack(csv_path, json_path=None, gexf_path=''):
    if json_path is None or not os.path.exists(json_path):
        print 'start: ' + csv_path
        map = dict()
        headers, packets = read_csv(csv_path, csv_filter=csv_filter_http)
        for packet in packets:
            if packet['SrcAddr'] not in map:
                map[packet['SrcAddr']] = []
            else:
                if packet['DstAddr'] not in map[packet['SrcAddr']]:
                    map[packet['SrcAddr']].append(packet['DstAddr'])
        json.dump(map, open(json_path, 'wb'))
    else:
        map = json.load(open(json_path, 'rb'))
    G = nx.Graph()
    edges = []
    for src in map:
        for dst in map[src]:
            edges.append((src, dst))
    G.add_edges_from(edges)
    color_map = []
    for node in G:
        if node in map:
            color_map.append('blue')
        else:
            color_map.append('red')

    for node in G.node:
        if node in map:
            G.node[node]['viz'] = {'color': {'r': 0, 'g': 0, 'b': 255, 'a': 0}}
        else:
            G.node[node]['viz'] = {'color': {'r': 255, 'g': 0, 'b': 0, 'a': 0}}
        # G.node[src]['label_fill'] = 'blue'


    if os.path.exists(gexf_path):
        os.remove(gexf_path)
    nx.write_gexf(G, gexf_path)

    pos = nx.spring_layout(G, scale=2)
    src = list(map.keys())
    dst = []
    for node in G.node:
        if node not in src:
            dst.append(node)
    labels = {}
    counts = 1
    countt = 1
    for node in G:
        if node in map:
            labels[node] = (str(counts))
            counts += 1
        else:
            labels[node] = (str(countt))
            countt += 1

    pos = nx.shell_layout(G, nlist=[src, dst])

    nx.draw(G, pos, scale=5, node_color=color_map, with_labels=False)


    nx.draw_networkx_labels(G, pos, labels)
    '''
    #nx.draw(G, cmap=plt.get_cmap('jet'), node_color=color_map)
    #nx.draw_circular(G, with_labels=False, center=list(map.keys()))
    # plt.plot([10,10,14,14,10],[2,4,4,2,2],'r')
    col_labels = ['index', 'ip']
    table_vals = []
    for label in labels:
        table_vals.append([label, labels[label]])
    # the rectangle is where I want to place the table
    the_table = plt.table(cellText=table_vals,
                          colWidths=[0.01] * 2,
                          colLabels=col_labels,
                          bbox=[0.25, -0.5, 0.5, 0.3],
                          loc='center right')
    plt.text(12, 3.4, 'Table Title', size=8)
    '''
    plt.show()

    #app = Viewer(G)
    #app.mainloop()


if __name__ == '__main__':
    print 'start'
    mapping_c2_attack('C:\Users\hfu\Documents/flows\CTU-13\CTU-13-9/0/'
                                      'capture20110817.binetflow.2format',
                      json_path='C:\Users\hfu\Documents/flows\CTU-13\CTU-13-9/0/'
                      'capture20110817.binetflow.cc.mapping.json',
                      gexf_path='C:\Users\hfu\Documents/flows\CTU-13\CTU-13-9/0/'
                      'capture20110817.binetflow.cc.mapping.gexf')
    '''
    
    
    headers, packets = read_csv('/mnt/Documents/flows/CTU-13/CTU-13-1/0/capture20110818.binetflow.2format',
                                csv_filter_http, label = 'SPAM')

    dirname = '/mnt/Documents/flows/CTU-13/CTU-13-10/0/'
    pcap = 'botnet-capture-20110810-neris.pcap'
    pkts = PcapHandler.get_packets(os.path.join(dirname, pcap))
    for packet in packets:
        PcapHandler.filter_pcap(dirname, pkts, packet['DstAddr'], packet['Sport'])
    '''