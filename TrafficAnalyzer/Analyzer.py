import os
import json
from utils import Utilities
import numpy as np


class Analyzer:
    logger = Utilities.set_logger('Analyzer')
    logger.setLevel(10)

    @staticmethod
    def preprocess(instances_dir_path):
        # Following the folds set by the AppInspection phase
        with open(os.path.join(instances_dir_path, 'instances.json'), 'r') as infile:
            instances = json.load(infile)
            print(len(instances))
            pred_negs = []
            with open(os.path.join(instances_dir_path, 'folds.json'), 'r') as json_file:
                folds = json.load(json_file)
                for fold in folds:
                    pred_negs.append([instances[instance] for instance in fold['vot_pred_neg']])
                print(pred_negs)


if __name__ == '__main__':
    instances_dir_path = "../AppInspector/data/Location/"
    Analyzer.preprocess(instances_dir_path)