from AppInspector.SharingInstance import SharingInstance, obj
import hashlib
import json
import os
from Learner import Learner
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from utils import Utilities
from sklearn import svm
from sklearn.linear_model import LogisticRegression
import pandas as pd


class InstanceHandler:
    logger = Utilities.set_logger('InstanceHandler')
    logger.setLevel(level=20)

    @staticmethod
    def docs(instances):
        docs = []
        labels = []
        for instance in instances:
            doc = []
            for string in instance.ui_doc:
                doc.append(' '.join(Learner.str2words(str(string))))
            docs.append(' '.join(doc))
            labels.append(int(instance.label))
        return docs, np.array(labels)

    @staticmethod
    def handle(root_dir):
        # instances_dir_name = hashlib.md5(root_dir.encode('utf-8')).hexdigest()
        instances_dir_path = os.path.join('data', os.path.basename(root_dir))
        pos_dir = os.path.join(root_dir, '1')
        pos_out_dir = os.path.join(instances_dir_path, '1')
        neg_dir = os.path.join(root_dir, '0')
        neg_out_dir = os.path.join(instances_dir_path, '0')
        if not os.path.exists(instances_dir_path):
            os.makedirs(pos_out_dir)
            instances = SharingInstance.instances(pos_dir)
            for instance in instances:
                with open(os.path.join(pos_out_dir, instance.id + '.json'), 'w', encoding="utf8") as outfile:
                    outfile.write(instance.json())

            os.makedirs(neg_out_dir)
            neg_instances = SharingInstance.instances(neg_dir)
            InstanceHandler.logger.info('neg: ' + str(len(neg_instances)))
            for instance in neg_instances:
                with open(os.path.join(neg_out_dir, instance.id + '.json'), 'w', encoding="utf8") as outfile:
                    outfile.write(instance.json())
            instances += neg_instances
        else:
            instances = []
            for dir_path in [pos_out_dir, neg_out_dir]:
                for root, dirs, files in os.walk(dir_path):
                    for file_name in files:
                        if file_name.endswith('.json'):
                            with open(os.path.join(root, file_name), 'r', encoding="utf8") as my_file:
                                instance = obj(json.load(my_file))
                                # print(instance.id)
                                instances.append(instance)
        docs, y = InstanceHandler.docs(instances)
        train_data, voc, vec = Learner.gen_X_matrix(docs)
        InstanceHandler.logger.info('neg: ' + str(len(np.where(y == 0)[0])))
        folds = Learner.n_folds(train_data, y, fold=10) #[Fold(f) for f in Learner.n_folds(train_data, y, fold=10)]
        """
        clf = DecisionTreeClassifier(class_weight='balanced')
        res = Learner.cross_validation(clf, folds)
        for fold in res['fold']:
            for item in fold['fp_item']:
                instance = instances[item]
                InstanceHandler.logger.info("FP:" + str(item) + str(instance.ui_doc) + "," + str(instance.dir))
            for item in fold['fn_item']:
                instance = instances[item]
                InstanceHandler.logger.info("FN:" + str(item) + str(instance.ui_doc) + "," + str(instance.dir))
        
        clf = MultinomialNB()
        Learner.cross_validation(clf, folds)
        clf = RandomForestClassifier(class_weight='balanced')
        Learner.cross_validation(clf, folds)
        clf = svm.SVC(kernel='linear', class_weight='balanced', probability=True)
        Learner.cross_validation(clf, folds)
        clf = LogisticRegression(class_weight='balanced')
        Learner.cross_validation(clf, folds)
        """
        clfs = [svm.SVC(kernel='linear', class_weight='balanced', probability=True),
                RandomForestClassifier(class_weight='balanced'),
                LogisticRegression(class_weight='balanced')]
        res, predicted_neg = Learner.voting(clfs, folds)
        predicted_neg_instances = []
        for negs in predicted_neg:
            predicted_neg_instances.append([instances[i] for i in negs])
        with open(os.path.join(instances_dir_path, 'folds.json'), 'w') as json_file:
            pd.Series(folds).to_json(json_file, orient='split')
        """
        with open(os.path.join(instances_dir_path, 'voting_res.json'), 'w') as json_file:
            pd.Series(res).to_json(json_file, orient='split')
            # json.dump(res, json_file)
        with open(os.path.join(instances_dir_path, 'voting_predicted_neg.json'), 'w') as json_file:
            json.dump(predicted_neg_instances, json_file)
        """


if __name__ == '__main__':
    root_dir = 'H:/FlowIntent/Location'
    InstanceHandler.handle(root_dir)