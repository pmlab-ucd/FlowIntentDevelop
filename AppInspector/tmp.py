from learner import Learner
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from scipy import sparse

docs = ['b b', '测试', '测试', '测试', '测试', 'b', 'b', 'b', 'b', 'a 测试']
numerical_features = [
    [1, 0],
    [1, 1],
    [0.8, 0],
    [0, 1],
    [1, 1],
    [0, 0],
    [2, 3],
    [1, 0],
    [1.1, 1],
    [0.3, 1]
]
labels = [0, 0, 0, 0, 0, 1, 1, 1, 1, 1]
y = np.array(labels)
train_data, voc, vec = Learner.LabelledDocs.vectorize(docs)
combinedFeatures = np.hstack([train_data.toarray(), numerical_features])
combinedFeatures = sparse.csr_matrix(combinedFeatures)
print(combinedFeatures)
print(voc)
folds = Learner.n_folds(combinedFeatures, y)
clf = DecisionTreeClassifier(class_weight='balanced')
res = Learner.cross_validation(clf, combinedFeatures, y, folds)
for fold in res['fold']:
    for i in fold['fp_item']:
        print(i, docs[i])
