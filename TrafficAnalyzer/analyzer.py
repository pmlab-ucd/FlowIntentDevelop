import json

from learner import Learner
from pcap_processor import *
from utils import Utilities

logger = Utilities.set_logger('Analyzer')


class Analyzer:
    logger.setLevel(10)

    @staticmethod
    def pred_pos_contexts(pred_contexts_path):
        """
        Retrieve the predicted positive (abnormal) "contexts" using the voting results given by ContextHandler.
        :param pred_contexts_path: Where the predicted contexts locate.
        :return pred_pos: predicted positive SharingInstances
        """
        with open(os.path.join(pred_contexts_path, 'pred_contexts.json'), 'r') as infile:
            pred_contexts = json.load(infile)
            logger.info(len(pred_contexts))
            pred_pos = []
            with open(os.path.join(pred_contexts_path, 'folds.json'), 'r') as json_file:
                folds = json.load(json_file)
                for fold in folds:
                    pred_pos.extend([pred_contexts[context] for context in fold['vot_pred_neg']])
                print(pred_pos)
            return pred_pos

    @staticmethod
    def pcaps(contexts: [dict]) -> []:
        """
        Given contexts, get the corresponding tainted pcap specified in instance['dir'] field.
        :param contexts:
        :return:
        """
        fls = []
        for instance in contexts:
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
            flows = http_requests(pcap['path'], filter_flow=filter_func, args=args)

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
    """
    Extract pos and neg pcaps from labelled context directories, and then transform them into jsons.
    """
    # Positive/Abnormal pcaps.
    contexts_dir = "../AppInspector/data/Location/"
    contexts = Analyzer.pred_pos_contexts(contexts_dir)
    pcaps = Analyzer.pcaps(contexts)
    Analyzer.pcap2jsons(pcaps, '1', 'data')

    # Negative/Normal pcaps.
    pcaps = []
    for root, dirs, files in os.walk('H:/FlowIntent/Location/pcap'):
        for file in files:
            if file.endswith('pcap'):
                pcaps.append({'path': os.path.join(root, file), 'label': '0'})
    Analyzer.pcap2jsons(pcaps, '0', 'data')


if __name__ == '__main__':
    preprocessed = False
    if not preprocessed:
        preprocess()

    instances, y = Learner.gen_instances(os.path.join('data', '1'),
                                         os.path.join('data', '0'), char_wb=False, simulate=False)
    X, feature_names, vec = Learner.gen_X_matrix(instances, tf=False)
    Learner.train_classifier(Learner.train_tree, X, y, 5, dict(), 'tree')