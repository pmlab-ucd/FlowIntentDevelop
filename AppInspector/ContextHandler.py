from AppInspector.Context import Context, Object, contexts
import json
import os
from Learner import Learner
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from utils import Utilities
from sklearn import svm
from sklearn.linear_model import LogisticRegression


class ContextHandler:
    """
    Gather the labelled app contexts and build the ML models.
    """
    logger = Utilities.set_logger('ContextHandler')

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
    def handle(root_dir, pos_dir_name='1', neg_dir_name='0'):
        """
        Given the dataset of legal and illegal sharing instances
        Perform cross-validation on them
        :param root_dir:
        :param pos_dir_name:
        :param neg_dir_name:
        """
        # Read the sharing instances stored in the hard disk and convert them into SharingInstances
        # instances_dir_name = hashlib.md5(root_dir.encode('utf-8')).hexdigest()
        # Output dir
        instances_dir_path = os.path.join('data', os.path.basename(root_dir))
        pos_dir = os.path.join(root_dir, pos_dir_name)
        pos_out_dir = os.path.join(instances_dir_path, pos_dir_name)
        neg_dir = os.path.join(root_dir, neg_dir_name)
        neg_out_dir = os.path.join(instances_dir_path, neg_dir_name)
        if not os.path.exists(instances_dir_path):
            os.makedirs(pos_out_dir)
            instances = contexts(pos_dir)
            for instance in instances:
                with open(os.path.join(pos_out_dir, instance.id + '.json'), 'w', encoding="utf8") as outfile:
                    outfile.write(instance.json())

            os.makedirs(neg_out_dir)
            neg_instances = contexts(neg_dir)
            ContextHandler.logger.info('neg: ' + str(len(neg_instances)))
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
                                # ContextHandler.logger.debug(instance.dir)
                                instances.append(instance)
            with open(os.path.join(instances_dir_path, 'instances.json'), 'w', encoding="utf8") as outfile:
                json.dump(instances_dict, outfile)
                # pd.Series(instances).to_json(outfile, orient='values')
        # Convert the SharingInstances into the <String, label> pairs
        docs, y = ContextHandler.docs(instances)
        # Transform the strings into the np array
        train_data, voc, vec = Learner.gen_X_matrix(docs)
        ContextHandler.logger.info('neg: ' + str(len(np.where(y == 0)[0])))
        ContextHandler.logger.info('pos: ' + str(len(np.where(y == 1)[0])))
        # Split the data set into 10 folds
        folds = Learner.n_folds(train_data, y, fold=10)  # [Fold(f) for f in Learner.n_folds(train_data, y, fold=10)]
        """
        # Perform the init classification and check the misclassified instances
        clf = DecisionTreeClassifier(class_weight='balanced')
        res = Learner.cross_validation(clf, folds)
        for fold in res['fold']:
            for item in fold['fp_item']:
                instance = instances[item]
                ContextHandler.logger.info("FP:" + str(item) + str(instance.ui_doc) + "," + str(instance.dir))
            for item in fold['fn_item']:
                instance = instances[item]
                ContextHandler.logger.info("FN:" + str(item) + str(instance.ui_doc) + "," + str(instance.dir))
        
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
            ContextHandler.logger.debug('CLF:' + clf_name)
            for fold in res[clf_name]:
                if 'fp_item' not in fold:
                    continue
                for fp in fold['fp_item']:
                    ContextHandler.logger.debug('FP:' + str(instances[fp].ui_doc) + "," + instances[fp].topic)
                for fn in fold['fn_item']:
                    ContextHandler.logger.debug('FN:' + str(instances[fn].ui_doc) + "," + instances[fn].topic)
        with open(os.path.join(instances_dir_path, 'folds.json'), 'w') as json_file:
            for fold in folds:
                fold['train_index'] = fold['train_index'].tolist()
                fold['test_index'] = fold['test_index'].tolist()
            # pd.Series(folds).to_json(json_file, orient='values')
            ContextHandler.logger.info(len(folds))
            json.dump(folds, json_file)
        """
        with open(os.path.join(instances_dir_path, 'voting_res.json'), 'w') as json_file:
            pd.Series(res).to_json(json_file, orient='split')
            json.dump(res, json_file)
        with open(os.path.join(instances_dir_path, 'voting_predicted_neg.json'), 'w') as json_file:
            json.dump(predicted_neg_instances, json_file)
        """


if __name__ == '__main__':
    root_dir = 'H:/FlowIntent/Location'
    ContextHandler.logger.setLevel(10)
    Learner.logger.setLevel(20)
    ContextHandler.handle(root_dir)