from utils import set_logger
import os
import logging
from multiprocessing import Manager, Pool
from pcap_processor import flows2json, logger as pcap_proc_log
from learner import Learner
import numpy as np
import json
from argparse import ArgumentParser
from sklearn.linear_model import LogisticRegression

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
            label = 1 if flow['label'] == '1' else 0
            real_label = 1 if flow['real_label'] == '1' else 0
            try:
                docs.append(Learner.LabelledDocs(line, label, real_label, char_wb=char_wb))
            except Exception as e:
                logger.warn(str(e) + ':' + str(line))
        return docs

    @staticmethod
    def gen_instances(positive_flows, negative_flows, simulate=False, char_wb=False):
        logger.info('lenPos: ' + str(len(positive_flows)))
        logger.info('lenNeg: ' + str(len(negative_flows)))
        docs = Analyzer.gen_docs(positive_flows, char_wb)
        docs = docs + (Analyzer.gen_docs(negative_flows, char_wb))
        if simulate:
            if len(negative_flows) == 0:
                docs = docs + Learner.simulate_flows(len(positive_flows), 0)
        samples = []
        labels = []
        real_labels = []
        for doc in docs:
            samples.append(doc.doc)
            labels.append(doc.label)
            real_labels.append(doc.real_label)
            logger.debug(str(doc.label) + ": " + doc.doc)

        return samples, np.array(labels), np.array(real_labels)

    @staticmethod
    def cross_validation(X, y, real_labels, clf, fold=5):
        folds = Learner.n_folds(X, y, fold=fold)
        results = dict()
        results['fold'] = []
        scores = []
        for fold in folds:
            result = dict()
            train_index = fold['train_index']
            test_index = fold['test_index']
            X_train, X_test = X[train_index], X[test_index]
            y_train, y_test = y[train_index], real_labels[test_index]
            # train the classifier
            clf.fit(X_train, y_train)
            # make the predictions
            predicted = clf.predict(X_test)
            y_plabs = np.squeeze(predicted)
            tp = len(np.where((y_plabs == 1) & (y_test == 1))[0])
            tn = len(np.where((y_plabs == 0) & (y_test == 0))[0])
            fp_i = np.where((y_plabs == 1) & (y_test == 0))[0]
            fp = len(fp_i)
            fn_i = np.where((y_plabs == 0) & (y_test == 1))[0]
            fn = len(fn_i)
            result['fp_item'] = test_index[fp_i]
            result['fn_item'] = test_index[fn_i]
            accuracy = float(tp + tn) / float(tp + tn + fp + fn)
            logger.info("Accuracy: " + str(accuracy))
            precision = float(tp) / float(tp + fp)
            recall = float(tp) / float(tp + fn)
            f_score = 2 * (precision * recall) / (precision + recall)
            result['f_score'] = f_score
            results['fold'].append(result)
            scores.append(f_score)
            logger.info("F-score: " + str(f_score) + ' Precision: ' + str(precision) + " Recall: " + str(recall))
        results['mean_scores'] = np.mean(scores)
        results['std_scores'] = np.std(scores)
        logger.info('mean scores:' + str(results['mean_scores']))
        return results


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

    instances, y, true_labels = Analyzer.gen_instances(pos_flows, neg_flows, char_wb=False, simulate=False)
    X, feature_names, vec = Learner.gen_X_matrix(instances, tf=False)
    Analyzer.cross_validation(X, y, true_labels, LogisticRegression(class_weight='balanced', penalty='l1'))
