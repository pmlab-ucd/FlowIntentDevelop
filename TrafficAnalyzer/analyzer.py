import json

from learner import Learner
from pcap_processor import *
import pcap_processor
from utils import set_logger
import shutil
import logging

logger = set_logger('Analyzer')


class Analyzer:
    @staticmethod
    def pred_pos_contexts(pred_contexts_path):
        """
        Retrieve the predicted positive (abnormal) "contexts" using the voting results given by ContextProcessor.
        :param pred_contexts_path: Where the predicted contexts locate.
        :return pred_pos: predicted positive contexts.
        """
        with open(os.path.join(pred_contexts_path, 'contexts.json'), 'r') as infile:
            contexts = json.load(infile)
            logger.info(len(contexts))
            pred_pos = []
            with open(os.path.join(pred_contexts_path, 'folds.json'), 'r') as json_file:
                folds = json.load(json_file)
                for fold in folds:
                    pred_pos.extend([contexts[context] for context in fold['vot_pred_pos']])
                logger.info(pred_pos)
            return pred_pos

    @staticmethod
    def pcaps(contexts: [dict]) -> []:
        """
        Given contexts, get the corresponding tainted pcap specified in context['dir'] field.
        :param contexts:
        :return:
        """
        fls = []
        for context in contexts:
            context_dir = context['dir']
            logger.debug(context_dir)
            for root, dirs, files in os.walk(context_dir):
                for file in files:
                    if 'filtered_' in file and str(file).endswith('pcap'):
                        fls.append({'path': os.path.join(root, file), 'label': context['label']})
        logger.info('The number of positive pcaps: %d', len(fls))
        return fls

    @staticmethod
    def pcap2jsons(pcaps, label, out_base_dir, filter_func=None, *args):
        """
        Generate a json file in out_dir for each given pcap.
        :param pcaps:
        :param label: The label given by the ML module of AppInspector, may not match the ground truth.
        :param out_base_dir:
        :param filter_func:
        :param args:
        :return:
        """
        filtered = []
        for pcap in pcaps:
            # Open up a test pcap file and print out the packets"""
            flows = http_requests(pcap['path'], filter_flow=filter_func, args=args)
            if flows is None:
                continue
            for flow in flows:
                flow['label'] = pcap['label']  # The label of ground truth.
                flow['path'] = pcap['path']
                filtered.append(flow)
        out_dir = os.path.join(out_base_dir, label)
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)
        else:
            shutil.rmtree(out_base_dir)
            os.makedirs(out_dir)
        logger.info('The number of the filtered flows: %d', len(filtered))
        for flow in filtered:
            timestamp = flow['timestamp'].replace(':', '-')
            timestamp = timestamp.replace('.', '-')
            timestamp = timestamp.replace(' ', '_')
            filename = str(flow['domain'] + '_' + timestamp + '.json').replace(':', '_').replace('/', '_')
            try:
                with open(os.path.join(out_dir, filename), 'w') as outfile:
                    json.dump(flow, outfile)
            except UnicodeDecodeError as e:
                    logger.warn(e)
        return filtered


def preprocess(negative_pcap_dir):
    """
    Extract pos and neg pcaps from labelled context directories, and then transform them into jsons.
    :param negative_pcap_dir: The directory of labelled negative (normal) pcaps.
    """
    # Positive/Abnormal pcaps.
    contexts_dir = "../AppInspector/data/Location/"
    contexts = Analyzer.pred_pos_contexts(contexts_dir)
    pcaps = Analyzer.pcaps(contexts)
    Analyzer.pcap2jsons(pcaps, '1', 'data')

    # Negative/Normal pcaps.
    pcaps = []
    for root, dirs, files in os.walk(negative_pcap_dir):
        for file in files:
            if file.endswith('pcap'):
                pcaps.append({'path': os.path.join(root, file), 'label': '0'})
    Analyzer.pcap2jsons(pcaps, '0', 'data')


if __name__ == '__main__':
    logger.setLevel(logging.INFO)
    pcap_processor.logger.setLevel(logging.INFO)
    neg_pcap_dir = sys.argv[1]
    logger.info('The negative pcap stored at: %s', neg_pcap_dir)
    preprocess(neg_pcap_dir)

    instances, y = Learner.gen_instances(os.path.join('data', '1'),
                                         os.path.join('data', '0'), char_wb=False, simulate=False)
    X, feature_names, vec = Learner.gen_X_matrix(instances, tf=False)
    Learner.train_classifier(Learner.train_tree, X, y, 5, dict(), 'tree')
