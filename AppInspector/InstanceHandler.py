from AppInspector.SharingInstance import SharingInstance, obj
import hashlib
import json
import os
from Learner import Learner
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import BernoulliNB
from sklearn.ensemble import RandomForestClassifier


class InstanceHandler:
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
            print(doc)
            print(instance.label)
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
            for instance in neg_instances:
                with open(os.path.join(neg_out_dir, instance.id + '.json'), 'w', encoding="utf8") as outfile:
                    outfile.write(instance.json())
            instances.append(neg_instances)
        else:
            instances = []
            for root, dirs, files in os.walk(instances_dir_path):
                for file_name in files:
                    if file_name.endswith('.json'):
                        with open(os.path.join(root, file_name), 'r', encoding="utf8") as my_file:
                            instance = obj(json.load(my_file))
                            # print(instance.id)
                            instances.append(instance)
        docs, y = InstanceHandler.docs(instances)
        train_data, voc, vec = Learner.gen_X_matrix(docs)
        folds = Learner.n_folds(train_data, y)
        clf = DecisionTreeClassifier(class_weight='balanced')
        Learner.cross_validation(clf, folds)
        clf = BernoulliNB()
        Learner.cross_validation(clf, folds)
        clf = RandomForestClassifier(class_weight='balanced')
        Learner.cross_validation(clf, folds)



if __name__ == '__main__':
    root_dir = 'H:/FlowIntent/Location'
    InstanceHandler.handle(root_dir)