from utils import set_logger
import pickle
from argparse import ArgumentParser
import os
import json
from TrafficAnalyzer.analyzer import Analyzer, gen_neg_flow_jsons
from learner import Learner

logger = set_logger('Predictor', 'INFO')


def predict(model_path: str, vec_path: str, data_dir_path: str):
    """
    Predict on any flow using the saved model.
    :param model_path: The path of a saved model.
    :param vec_path: sklearn.feature_extraction.text.CountVectorizer
    :param data_dir_path: The path of the test flows. /home/workspace/FlowIntent/data/Location/cxt/0
    """
    model = pickle.load(open(model_path, 'rb'))
    vec = pickle.load(open(vec_path, 'rb'))
    # Negative/Normal pcaps.
    # They have no relationship with "context" defined in AppInspector, just a bunch of normal flows.
    test_flows = []
    for root, dirs, files in os.walk(data_dir_path):
        for file in files:
            if file.endswith('_http_flows.json'):
                with open(os.path.join(root, file), 'r', encoding="utf8", errors='ignore') as infile:
                    flows = json.load(infile)
                    for flow in flows:
                        # The context label is as same as the ground truth since they are not labelled by AppInspector.
                        flow['real_label'] = '0'
                        test_flows.append(flow)
    logger.info('The number of test flows %d', len(test_flows))
    # Covert flows to a feature matrix.
    text_fea, numeric_fea, y, true_labels = Analyzer.gen_instances(test_flows, [])
    X, feature_names, vec = Learner.LabelledDocs.vectorize(text_fea, vec=vec, tf=False)
    # Prediction.
    res = model.predict(X)


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-m", "--model", dest="model",
                        help="the full path of the saved model")
    parser.add_argument("-v", "--vec", dest="vec",
                        help="the full path of the saved vocabulary")
    parser.add_argument("-d", "--data", dest="data",
                        help="the path of data needed to be predicted")
    parser.add_argument("-j", "--jsons", dest="jsons", action='store_true',
                        help="is it needed to first generate http_flows.json?")
    parser.add_argument("-p", "--proc", dest="proc_num", default=4,
                        help="the number of processes used in multiprocessing")
    args = parser.parse_args()
    if args.jsons:
        logger.info('Generate flow jsons ...')
        gen_neg_flow_jsons(args.data, args.proc_num, has_sub_dir=True)
    predict(args.model, args.vec, args.data)
