import os
import json
from utils import Utilities
from TrafficAnalyzer.PcapHandler import PcapHandler
from Learner import Learner


class Analyzer:
    logger = Utilities.set_logger('Analyzer')
    logger.setLevel(10)

    @staticmethod
    def instances(instances_dir_path):
        """
        Retrieve the predicted neg SharingInstances using the voting results given by the InstanceHandler
        :param instances_dir_path:
        :return pred_negs: predicted neg SharingInstances
        """
        with open(os.path.join(instances_dir_path, 'instances.json'), 'r') as infile:
            instances = json.load(infile)
            print(len(instances))
            pred_negs = []
            with open(os.path.join(instances_dir_path, 'folds.json'), 'r') as json_file:
                folds = json.load(json_file)
                for fold in folds:
                    pred_negs.extend([instances[instance] for instance in fold['vot_pred_neg']])
                print(pred_negs)
            return pred_negs

    @staticmethod
    def pcaps(instances: [dict]) -> []:
        """
        Given sharing instances, get the corresponding tainted pcap
        :param instances:
        :return:
        """
        fls = []
        for instance in instances:
            instance_dir = instance['dir']
            for root, dirs, files in os.walk(instance_dir):
                for file in files:
                    if 'filtered_' in file and str(file).endswith('pcap'):
                        fls.append({'path': os.path.join(root, file), 'label': instance['label']})
        print(len(fls))
        return fls

    @staticmethod
    def pcap2jsons(pcaps, label, out_base_dir, filter_func=None, *args):
        """
        Generate a json file in out_dir for each given pcap
        :param pcaps:
        :param label: The label given by the ML module in AppInspector, may not be the ground truth
        :param out_base_dir:
        :param filter_func:
        :param args:
        :return:
        """
        filtered = []
        for pcap in pcaps:
            # Open up a test pcap file and print out the packets"""
            flows = PcapHandler.http_requests(pcap['path'], filter_flow=filter_func, args=args)

            for flow in flows:
                flow['label'] = pcap['label']  # The ground truth label
                flow['path'] = pcap['path']
                filtered.append(flow)
        out_dir = os.path.join(out_base_dir, label)
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
                    print(e)
        return filtered


def preprocess():
    instances_dir_path = "../AppInspector/data/Location/"
    instances = Analyzer.instances(instances_dir_path)
    pcaps = Analyzer.pcaps(instances)
    Analyzer.pcap2jsons(pcaps, '0', 'data')

    # Normal pcap
    pos_pcap = []
    for root, dirs, files in os.walk('/Users/haof/Documents/FlowIntent/Location/pcap'):
        for file in files:
            if file.endswith('pcap'):
                pos_pcap.append({'path': os.path.join(root, file), 'label': '1'})
    Analyzer.pcap2jsons(pos_pcap, '1', 'data')


if __name__ == '__main__':
    already_preprocess = False
    if not already_preprocess:
        preprocess()

    instances, y = Learner.gen_instances(os.path.join('data', '1'),
                                         os.path.join('data', '0'), char_wb=False, simulate=False)
    X, feature_names, vec = Learner.gen_X_matrix(instances, tf=False)
    Learner.train_classifier(Learner.train_tree, X, y, 5, dict(), 'tree')