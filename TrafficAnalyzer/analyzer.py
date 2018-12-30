from utils import set_logger
import os
import logging
from multiprocessing import Manager, Pool
from pcap_processor import flows2json, logger as pcap_proc_log
from learner import Learner
import numpy as np
import json
from argparse import ArgumentParser

logger = set_logger('Analyzer', 'INFO')


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
    def sens_flow_jsons(contexts: [dict]) -> []:
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
                        with open(os.path.join(root, file), 'r', encoding="utf8", errors='ignore') as infile:
                            flows = json.load(infile)
                            for flow in flows:
                                # The ground truth label, which is defined by "context" label.
                                flow['real_label'] = context['label']
                                jsons.append(flow)
        logger.info('The number of flows: %d', len(jsons))
        return jsons

    @staticmethod
    def gen_docs(jsons, char_wb=False):
        docs = []
        for flow in jsons:
            line = flow['url']
            label = 1 if flow['label'] == '1' else -1
            try:
                docs.append(Learner.LabelledDocs(line, label, char_wb=char_wb))
            except Exception as e:
                logger.warn(str(e) + ':' + str(line))
        return docs

    @staticmethod
    def gen_instances(pos_flows, neg_flows, simulate=False, char_wb=False):
        logger.info('lenPos: ' + str(len(pos_flows)))
        logger.info('lenNeg: ' + str(len(neg_flows)))
        docs = Analyzer.gen_docs(pos_flows, char_wb)
        docs = docs + (Analyzer.gen_docs(neg_flows, char_wb))
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


def flows2jsons(negative_pcap_dir, label, json_ext, visited_pcap):
    for filename in os.listdir(negative_pcap_dir):
        if filename in visited_pcap:
            continue
        else:
            visited_pcap[filename] = 1
        flows2json(negative_pcap_dir, filename, label=label, json_ext=json_ext)


def flow2json_mp_wrapper(args):
    flows2jsons(*args)


def gen_neg_flow_jsons(negative_pcap_dir, proc_num=4):
    """
    :param negative_pcap_dir: The directory of labelled negative (normal) pcaps.
    :param proc_num:
    """
    visited = Manager().dict()
    p = Pool(proc_num)
    p.map(flow2json_mp_wrapper, [(negative_pcap_dir, '0', '_http_flows.json', visited)] * proc_num)
    p.close()


def preprocess(negative_pcap_dir):
    """
    Extract pos and neg pcaps from labelled context directories, and then transform them into jsons.
    :param negative_pcap_dir: The directory of labelled negative (normal) pcaps.
    """
    # Positive/Abnormal pcaps.
    contexts_dir = "../AppInspector/data/Location/"
    contexts = Analyzer.pred_pos_contexts(contexts_dir)
    positive_flows = Analyzer.sens_flow_jsons(contexts)
    for flow in positive_flows:
        # The label given by the prediction of AppInspector, may not be as same as the ground truth.
        flow['label'] = '1'

    # Negative/Normal pcaps.
    # They have no relationship with "context" defined in AppInspector, just a bunch of normal flows.
    negative_flows = []
    for file in os.listdir(negative_pcap_dir):
        if file.endswith('_http_flows.json'):
            with open(os.path.join(negative_pcap_dir, file), 'r', encoding="utf8", errors='ignore') as infile:
                flows = json.load(infile)
                for flow in flows:
                    # The context label is as same as the ground truth since they are not labelled by AppInspector.
                    flow['real_label'] = '0'
                    negative_flows.append(flow)

    return positive_flows, negative_flows


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-n", "--negdir", dest="neg_pcap_dir",
                        help="the full path of the dir that stores pcap files labelled as normal")
    parser.add_argument("-j", "--json", dest="gen_json", action='store_true',
                        help="if the jsons of the flows are not generated, generate")
    parser.add_argument("-l", "--log", dest="log", default='INFO',
                        help="the log level, such as INFO, DEBUG")
    parser.add_argument("-p", "--proc", dest="proc_num", default=4,
                        help="the number of processes used in multiprocessing")
    args = parser.parse_args()

    if args.log != 'INFO':
        logger = set_logger('Analyzer', args.log)
    pcap_proc_log.setLevel(logging.INFO)
    neg_pcap_dir = args.neg_pcap_dir
    logger.info('The negative pcaps are stored at: %s', neg_pcap_dir)
    if args.gen_json:
        gen_neg_flow_jsons(neg_pcap_dir, args.proc_num)
    pos_flows, neg_flows = preprocess(neg_pcap_dir)

    instances, y = Analyzer.gen_instances(pos_flows, neg_flows, char_wb=False, simulate=False)
    X, feature_names, vec = Learner.gen_X_matrix(instances, tf=False)
    Learner.train_classifier(Learner.train_tree, X, y, 5, dict(), 'tree')
