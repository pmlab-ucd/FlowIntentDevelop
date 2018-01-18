from AppInspector.SharingInstance import SharingInstance, obj
import hashlib
import json
import os
from Learner import Learner
import numpy as np


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
            labels.append(instance.label)
        return docs, np.array(labels)

    @staticmethod
    def handle(root_dir):
        instances_dir_name = hashlib.md5(root_dir.encode('utf-8')).hexdigest()
        instances_dir_path = os.path.join('data', instances_dir_name)
        if not os.path.exists(instances_dir_path):
            os.makedirs(instances_dir_path)
            instances = SharingInstance.instances(root_dir)
            for instance in instances:
                with open(os.path.join(instances_dir_path, instance.id + '.json'), 'w', encoding="utf8") as outfile:
                    outfile.write(instance.json())
        else:
            instances = []
            for root, dirs, files in os.walk(instances_dir_path):
                for file_name in files:
                    if file_name.endswith('.json'):
                        with open(os.path.join(root, file_name), 'r', encoding="utf8") as myfile:
                            instance = obj(json.load(myfile))
                            print(instance.id)
                            instances.append(instance)
        docs, y = InstanceHandler.docs(instances)
        print(len(docs))
        print(Learner.gen_X_matrix(docs))


if __name__ == '__main__':
    root_dir = 'C:/Users/hao/Documents/Ground/0/'
    InstanceHandler.handle(root_dir)