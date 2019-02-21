from AppInspector.context import Context, Object, contexts
import json
import os
from learner import Learner
import learner
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from utils import set_logger
from sklearn import svm
from sklearn.linear_model import LogisticRegression
import sys
import shutil
import pandas as pd
import logging
from multiprocessing import Manager, Pool

logger = set_logger('ContextProcessor')


class ContextProcessor:
    """
    Gather the labelled app contexts and build the ML models.
    """

    @staticmethod
    def docs(instances: [Context]) -> [[], []]:
        """
        Convert SharingInstances into the <string, label> pairs.
        :param instances:
        :return:
        """
        docs = []
        labels = []
        for instance in instances:
            doc = []
            for string in instance.ui_doc:
                doc.append(' '.join(Learner.str2words(str(string))))
            doc.append(instance.topic)
            docs.append(' '.join(doc))
            labels.append(int(instance.label))
        return docs, np.array(labels)

    @staticmethod
    def subprocess_mp_wrapper(args):
        return ContextProcessor.subprocess(*args)

    @staticmethod
    def subprocess(dir_path, instances):
        for root, dirs, files in os.walk(dir_path):
            for file_name in files:
                if not file_name.endswith('.json'):
                    continue
                with open(os.path.join(root, file_name), 'r', encoding="utf8", errors='ignore') as my_file:
                    instance = json.load(my_file)
                    instances.append(instance)
                    logger.debug(instance['dir'])

    @staticmethod
    def process(root_dir, pos_dir_name='1', neg_dir_name='0', reset_out_dir=False, sub_dir_name=''):
        """
        Given the dataset of legal and illegal sharing text_fea
        Perform cross-validation on them
        :param root_dir:
        :param pos_dir_name:
        :param neg_dir_name:
        :param reset_out_dir:
        :param sub_dir_name:
        """
        # Load the contexts stored in the hard disk.
        # instances_dir_name = hashlib.md5(root.encode('utf-8')).hexdigest()
        # Output dir
        contexts_dir = os.path.join('data', sub_dir_name)
        pos_dir = os.path.join(root_dir, pos_dir_name)
        pos_out_dir = os.path.join(contexts_dir, pos_dir_name)
        neg_dir = os.path.join(root_dir, neg_dir_name)
        neg_out_dir = os.path.join(contexts_dir, neg_dir_name)
        if reset_out_dir:
            shutil.rmtree(contexts_dir)
        if not os.path.exists(contexts_dir):
            os.makedirs(pos_out_dir)
            instances = contexts(pos_dir)
            logger.info('pos: %d', len(instances))
            for instance in instances:
                with open(os.path.join(pos_out_dir, instance.id + '.json'), 'w', encoding="utf8") as outfile:
                    outfile.write(instance.json())

            os.makedirs(neg_out_dir)
            instances = contexts(neg_dir)
            logger.info('neg: %d', len(instances))
            for instance in instances:
                with open(os.path.join(neg_out_dir, instance.id + '.json'), 'w', encoding="utf8") as outfile:
                    outfile.write(instance.json())
        m = Manager()
        pos_instances = m.list()
        neg_instances = m.list()
        p = Pool(2)
        p.map(ContextProcessor.subprocess_mp_wrapper,
              [(pos_out_dir, pos_instances), (neg_out_dir, neg_instances)])
        p.close()
        pos_instances.extend(neg_instances)
        instances = [i for i in pos_instances]
        with open(os.path.join(contexts_dir, 'contexts.json'), 'w', encoding="utf8") as outfile:
            json.dump(instances, outfile)
            logger.info("Generate contexts.json at %s", str(os.path.curdir))
            # pd.Series(text_fea).to_json(outfile, orient='values')
        return [Object(ins) for ins in instances], contexts_dir

    @staticmethod
    def train(instances, contexts_dir):
        # Convert the text_fea into the <String, label> pairs.
        docs, y = ContextProcessor.docs(instances)
        # Transform the strings into the np array.
        train_data, voc, vec = Learner.LabelledDocs.vectorize(docs)
        logger.info('neg: %d', len(np.where(y == 0)[0]))
        logger.info('pos: %d', len(np.where(y == 1)[0]))
        # Split the data set into 10 folds.
        folds = Learner.n_folds(train_data, y, fold=10)  # [Fold(f) for f in Learner.n_folds(train_data, y, fold=10)]
        """
        # Perform the init classification and check the misclassified text_fea
        clf = DecisionTreeClassifier(class_weight='balanced')
        res = Learner.cross_validation(clf, folds)
        for fold in res['fold']:
            for item in fold['fp_item']:
                instance = text_fea[item]
                ContextProcessor.log.info("FP:" + str(item) + str(instance.ui_doc) + "," + str(instance.dir))
            for item in fold['fn_item']:
                instance = text_fea[item]
                ContextProcessor.log.info("FN:" + str(item) + str(instance.ui_doc) + "," + str(instance.dir))
        
        clf = MultinomialNB()
        Learner.cross_validation(clf, folds)
        clf = RandomForestClassifier(class_weight='balanced')
        Learner.cross_validation(clf, folds)
        clf = svm.SVC(kernel='linear', class_weight='balanced', probability=True)
        Learner.cross_validation(clf, folds)
        clf = LogisticRegression(class_weight='balanced')
        Learner.cross_validation(clf, folds)
        """
        # Wrap a bunch of classifiers and let them vote on every fold.
        clfs = [svm.SVC(kernel='linear', class_weight='balanced', probability=True),
                RandomForestClassifier(class_weight='balanced'),
                LogisticRegression(class_weight='balanced')]
        res = Learner.voting(clfs, train_data, y, folds)
        for clf in clfs:
            clf_name = type(clf).__name__
            logger.debug('CLF: %s', clf_name)
            for fold in res[clf_name]:
                if 'fp_item' not in fold:
                    continue
                for fp in fold['fp_item']:
                    logger.debug('FP: %s, %s', str(instances[fp].ui_doc), instances[fp].topic)
                for fn in fold['fn_item']:
                    logger.debug('FN: %s, %s', str(instances[fn].ui_doc), instances[fn].topic)
        with open(os.path.join(contexts_dir, 'folds.json'), 'w') as json_file:
            for fold in folds:
                fold['train_index'] = fold['train_index'].tolist()
                fold['test_index'] = fold['test_index'].tolist()
            # pd.Series(folds).to_json(json_file, orient='values')
            logger.info('The number of folds: %d', len(folds))
            json.dump(folds, json_file)

        with open(os.path.join(contexts_dir, 'voting_res.json'), 'w') as json_file:
            pd.Series(res).to_json(json_file, orient='split')
        #   json.dump(res, json_file)
        # with open(os.path.join(contexts_dir, 'voting_predicted_pos.json'), 'w') as json_file:
        # json.dump(predicted_pos_instances, json_file)


if __name__ == '__main__':
    root = sys.argv[len(sys.argv) - 1]
    reset = False
    if len(sys.argv) > 1:
        reset = True if '-r' in sys.argv else reset
    logger.setLevel(logging.DEBUG)
    logger.info('The data stored at: %s', root)
    learner.logger.setLevel(logging.INFO)
    samples, samples_dir = ContextProcessor.process(root, reset_out_dir=reset, sub_dir_name=str(os.path.basename(root)))
    ContextProcessor.train(samples, samples_dir)
