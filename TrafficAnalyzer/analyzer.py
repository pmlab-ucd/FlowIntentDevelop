from utils import set_logger
import os
import logging
import sys
from pcap_processor import flows2jsons, logger as pcap_proc_log
from learner import Learner
import numpy as np
import json

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
    def flow_jsons(contexts: [dict]) -> []:
        """
        Given contexts, get the corresponding sens_http_flows.json specified in context['dir'] field.
        :param contexts:
        :return:
        """
        jsons = []
        for context in contexts:
            context_dir = context['dir']
            logger.debug(context_dir)
            for root, dirs, files in os.walk(context_dir):
                for file in files:
                    if file.endswith('_sens_http_flows.json'):
                        with open(os.path.join(root, file), 'r') as infile:
                            flows = json.load(infile)
                            for flow in flows:
                                # The label given by the learning module of AppInspector, may not be the ground truth.
                                flow['ctx_label'] = context['label']
                                jsons.append(flow)
        logger.info('The number of flows: %d', len(jsons))
        return jsons

    @staticmethod
    def gen_docs(jsons, label, char_wb=False):
        docs = []
        for flow in jsons:
            line = flow['url']
            try:
                docs.append(Learner.LabelledDocs(line, label, char_wb=char_wb))
            except Exception as e:
                logger.warn(str(e) + ':' + str(line))
        return docs

    @staticmethod
    def gen_instances(pos_flows, neg_flows, simulate=False, char_wb=False):
        logger.info('lenPos: ' + str(len(pos_flows)))
        logger.info('lenNeg: ' + str(len(neg_flows)))
        docs = Analyzer.gen_docs(pos_flows, 1, char_wb)
        docs = docs + (Analyzer.gen_docs(neg_flows, -1, char_wb))
        if simulate:
            if len(neg_flows) == 0:
                docs = docs + Learner.simulate_flows(len(pos_flows), 0)
        samples = []
        labels = []
        for doc in docs:
            samples.append(doc.doc)
            labels.append(doc.label)
            logger.debug(str(doc.label) + ": " + doc.doc)

        return samples, np.array(labels)


def preprocess(negative_pcap_dir):
    """
    Extract pos and neg pcaps from labelled context directories, and then transform them into jsons.
    :param negative_pcap_dir: The directory of labelled negative (normal) pcaps.
    """
    # Positive/Abnormal pcaps.
    contexts_dir = "../AppInspector/data/Location/"
    contexts = Analyzer.pred_pos_contexts(contexts_dir)
    pos_flows = Analyzer.flow_jsons(contexts)
    for flow in pos_flows:
        flow['label'] = '1'

    # Negative/Normal pcaps.
    neg_flows = []
    neg_flows = flows2jsons(negative_pcap_dir, neg_flows, label='0')
    for flow in neg_flows:
        # The context label is as same as ground truth since they are not labelled by AppInspector.
        flow['cxt_label'] = '0'
    return pos_flows, neg_flows


if __name__ == '__main__':
    logger.setLevel(logging.INFO)
    pcap_proc_log.setLevel(logging.INFO)
    neg_pcap_dir = sys.argv[1]
    logger.info('The negative pcap stored at: %s', neg_pcap_dir)
    preprocess(neg_pcap_dir)

    instances, y = Analyzer.gen_instances(os.path.join('data', '1'),
                                          os.path.join('data', '0'), char_wb=False, simulate=False)
    X, feature_names, vec = Learner.gen_X_matrix(instances, tf=False)
    Learner.train_classifier(Learner.train_tree, X, y, 5, dict(), 'tree')
