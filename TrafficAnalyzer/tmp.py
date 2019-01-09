import numpy as np

X = [
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
y = [0, 0, 0, 0, 0, 1, 1, 1, 1, 1]

X = np.array(X)
y = np.array(y)
sel = X[np.where(y == 1)]
print(np.concatenate((np.zeros(10), (-1 * np.ones(sel.shape[0])))))


