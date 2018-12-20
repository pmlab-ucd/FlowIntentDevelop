from AppInspector.context import Context, Object, contexts
import json
import os
from learner import Learner
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from utils import set_logger
from sklearn import svm
from sklearn.linear_model import LogisticRegression
import sys
import shutil

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
    def process(root_dir, pos_dir_name='1', neg_dir_name='0', reset_out_dir=False):
        """
        Given the dataset of legal and illegal sharing instances
        Perform cross-validation on them
        :param root_dir:
        :param pos_dir_name:
        :param neg_dir_name:
        :param reset_out_dir:
        """
        # Load the contexts stored in the hard disk.
        # instances_dir_name = hashlib.md5(root_dir.encode('utf-8')).hexdigest()
        # Output dir
        contexts_dir = os.path.join('data', os.path.basename(root_dir))
        pos_dir = os.path.join(root_dir, pos_dir_name)
        pos_out_dir = os.path.join(contexts_dir, pos_dir_name)
        neg_dir = os.path.join(root_dir, neg_dir_name)
        neg_out_dir = os.path.join(contexts_dir, neg_dir_name)
        if reset_out_dir:
            shutil.rmtree(contexts_dir)
        if not os.path.exists(contexts_dir):
            os.makedirs(pos_out_dir)
            instances = contexts(pos_dir)
            for instance in instances:
                with open(os.path.join(pos_out_dir, instance.id + '.json'), 'w', encoding="utf8") as outfile:
                    outfile.write(instance.json())

            os.makedirs(neg_out_dir)
            neg_instances = contexts(neg_dir)
            logger.info('neg: ' + str(len(neg_instances)))
            for instance in neg_instances:
                with open(os.path.join(neg_out_dir, instance.id + '.json'), 'w', encoding="utf8") as outfile:
                    outfile.write(instance.json())
            instances += neg_instances
        else:
            instances = []
            instances_dict = []
            for dir_path in [pos_out_dir, neg_out_dir]:
                for root, dirs, files in os.walk(dir_path):
                    for file_name in files:
                        if file_name.endswith('.json'):
                            with open(os.path.join(root, file_name), 'r', encoding="utf8") as my_file:
                                instance = json.load(my_file)
                                instances_dict.append(instance)
                                instance = Object(instance)
                                # ContextProcessor.logger.debug(instance.dir)
                                instances.append(instance)
            with open(os.path.join(contexts_dir, 'instances.json'), 'w', encoding="utf8") as outfile:
                json.dump(instances_dict, outfile)
                # pd.Series(instances).to_json(outfile, orient='values')
        # Convert the SharingInstances into the <String, label> pairs
        docs, y = ContextProcessor.docs(instances)
        # Transform the strings into the np array
        train_data, voc, vec = Learner.gen_X_matrix(docs)
        logger.info('neg: ' + str(len(np.where(y == 0)[0])))
        logger.info('pos: ' + str(len(np.where(y == 1)[0])))
        # Split the data set into 10 folds
        folds = Learner.n_folds(train_data, y, fold=10)  # [Fold(f) for f in Learner.n_folds(train_data, y, fold=10)]
        """
        # Perform the init classification and check the misclassified instances
        clf = DecisionTreeClassifier(class_weight='balanced')
        res = Learner.cross_validation(clf, folds)
        for fold in res['fold']:
            for item in fold['fp_item']:
                instance = instances[item]
                ContextProcessor.logger.info("FP:" + str(item) + str(instance.ui_doc) + "," + str(instance.dir))
            for item in fold['fn_item']:
                instance = instances[item]
                ContextProcessor.logger.info("FN:" + str(item) + str(instance.ui_doc) + "," + str(instance.dir))
        
        clf = MultinomialNB()
        Learner.cross_validation(clf, folds)
        clf = RandomForestClassifier(class_weight='balanced')
        Learner.cross_validation(clf, folds)
        clf = svm.SVC(kernel='linear', class_weight='balanced', probability=True)
        Learner.cross_validation(clf, folds)
        clf = LogisticRegression(class_weight='balanced')
        Learner.cross_validation(clf, folds)
        """
        # Wrap a bunch of classifiers and let them voting on each fold
        clfs = [svm.SVC(kernel='linear', class_weight='balanced', probability=True),
                RandomForestClassifier(class_weight='balanced'),
                LogisticRegression(class_weight='balanced')]
        res = Learner.voting(clfs, train_data, y, folds)
        for clf in clfs:
            clf_name = type(clf).__name__
            logger.debug('CLF:' + clf_name)
            for fold in res[clf_name]:
                if 'fp_item' not in fold:
                    continue
                for fp in fold['fp_item']:
                    logger.debug('FP:' + str(instances[fp].ui_doc) + "," + instances[fp].topic)
                for fn in fold['fn_item']:
                    logger.debug('FN:' + str(instances[fn].ui_doc) + "," + instances[fn].topic)
        with open(os.path.join(contexts_dir, 'folds.json'), 'w') as json_file:
            for fold in folds:
                fold['train_index'] = fold['train_index'].tolist()
                fold['test_index'] = fold['test_index'].tolist()
            # pd.Series(folds).to_json(json_file, orient='values')
            logger.info(len(folds))
            json.dump(folds, json_file)
        """
        with open(os.path.join(instances_dir_path, 'voting_res.json'), 'w') as json_file:
            pd.Series(res).to_json(json_file, orient='split')
            json.dump(res, json_file)
        with open(os.path.join(instances_dir_path, 'voting_predicted_neg.json'), 'w') as json_file:
            json.dump(predicted_neg_instances, json_file)
        """


if __name__ == '__main__':
    root_dir = sys.argv[len(sys.argv) - 1]
    reset = False
    if len(sys.argv) > 1:
        reset = True if '-r' in sys.argv else False
    logger.setLevel(10)
    logger.info('The data stored at: ', root_dir)
    Learner.logger.setLevel(20)
    ContextProcessor.process(root_dir, reset_out_dir=reset)
