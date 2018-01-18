from Learner import Learner
import numpy as np
from sklearn.tree import DecisionTreeClassifier

docs = ['b', '测试', '测试', '测试', '测试', 'b', 'b', 'b', 'b', '测试']
labels = [0, 0, 0, 0, 0, 1, 1, 1, 1, 1]
y = np.array(labels)
train_data, voc, vec = Learner.gen_X_matrix(docs)
print(voc)
folds = Learner.n_folds(train_data, y)
clf = DecisionTreeClassifier(class_weight='balanced')
Learner.cross_validation(clf, folds)

