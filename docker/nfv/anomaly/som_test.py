import pickle
import numpy as np
from sparse_som import *

def mu_std_dist(centroid, sparse_vectors):
    d = [np.sqrt(np.sum((centroid - x.A[0])**2)) for x in sparse_vectors]
    mu = np.mean(d)
    si = np.std(d)
    return mu, si

def accuracy(labels, predictions, ports=[], port=None):
    if port is not None and ports is not []:
        idx = np.where(np.array(ports) == port)[0]
        labels = labels[idx]
        predictions = predictions[idx]
    acc = float(len(np.where(labels == predictions)[0]))/len(labels)
    tpr = float(len(np.where((labels == predictions) & (labels > 0))[0]))/len(np.where(labels > 0)[0])
    fpr = float(len(np.where((labels == 0) & (predictions > 0))[0])) / len(np.where(labels == 0)[0])
    return acc, tpr, fpr

def train_som(x_train, x_test, y_test, p_test, n_clusters=24, alpha=97):
    _, N = x_train.shape
    som = Som(n_clusters, n_clusters, N, topology.HEXA)  # , verbose=True
    print(som.nrows, som.ncols, som.dim)
    som.codebook = np.random.rand(n_clusters, n_clusters, N).astype(som.codebook.dtype, copy=False)
    som.train(x_train)
    bmus = som.bmus(x_train)
    rad = np.zeros((n_clusters, n_clusters))
    for i in range(n_clusters):
        for j in range(n_clusters):
            ids = np.where((bmus[:, 0] == i) & (bmus[:, 1] == j))[0]
            if len(ids) > 0:
                vectors = [x_train[idx] for idx in ids]
                mu, si = mu_std_dist(som.codebook[i, j, :], vectors)
                rad[i, j] = mu + alpha * si
    radv = rad.reshape(n_clusters*n_clusters)
    n_test = x_test.shape[0]
    d_test = np.zeros((n_test, n_clusters * n_clusters))
    for i in range(n_clusters):
        for j in range(n_clusters):
            d_test[:, i * n_clusters + j] = np.hstack(
                [np.sqrt(np.sum((som.codebook[i, j, :] - x.A[0]) ** 2)) for x in x_test]
            )
    d_test_argmin = np.argmin(d_test, axis=1)
    labels = np.zeros(n_test)
    for i in range(n_test):
        j = d_test_argmin[i]
        if d_test[i, j] > radv[j]:
            labels[i] = 1
    acc, tpr, fpr = accuracy(np.array(y_test), labels, ports=p_test, port=80)
    print(acc, tpr, fpr)
    return som.codebook, rad

def test_som(x_train, x_test, n_clusters=10, alpha=3):
    _, N = x_train.shape  # Nb. features (vectors dimension)
    som = Som(n_clusters, n_clusters, N, topology.HEXA)  # , verbose=True
    print(som.nrows, som.ncols, som.dim)
    som.codebook = np.random.rand(n_clusters, n_clusters, N).astype(som.codebook.dtype, copy=False)
    som.train(x_train)
    bmus = som.bmus(x_train)
    u_bmus = np.unique(bmus, axis=0)
    rad = np.zeros((len(u_bmus), alpha - 1))
    for i in range(len(u_bmus)):
        ids = np.where((bmus[:, 0] == u_bmus[i][0]) & (bmus[:, 1] == u_bmus[i][1]))[0]
        vectors = [x_train[idx] for idx in ids]
        mu, si = mu_std_dist(som.codebook[u_bmus[i, 0], u_bmus[i, 1], :], vectors)
        for j in range(alpha - 1):
            rad[i, j] = mu + (j + 1) * si
    n_test = x_test.shape[0]
    d_test = np.zeros((n_test, len(u_bmus)))
    for i in range(len(u_bmus)):
        d_test[:,i] = np.hstack([np.sqrt(np.sum((som.codebook[u_bmus[i, 0], u_bmus[i, 1], :] - x.A[0])**2)) for x in x_test])
    d_test_argmin = np.argmin(d_test,axis=1)
    labels = np.zeros((n_test, alpha - 1))
    for i in range(n_test):
        j = d_test_argmin[i]
        for a in range(alpha - 1):
            if d_test[i, j] > rad[j, a]:
                labels[i, a] = 1
    return labels

if __name__ == '__main__':
    n = 2
    ngram_fname = '{0}grams_short.pkl'.format(n)
    with open(ngram_fname, 'rb') as f:
        x_train = pickle.load(f)
        x_test = pickle.load(f)
        ss = pickle.load(f)
        mas = pickle.load(f)
        y_test = pickle.load(f)
        p_train = pickle.load(f)
        p_test = pickle.load(f)
    codebook, rad = train_som(x_train, x_test, y_test, p_test)
    with open('som.pkl', 'wb') as f:
        pickle.dump(codebook, f)
        pickle.dump(rad, f)
        pickle.dump(ss, f)
        pickle.dump(mas, f)

    """
    
    uports = list(set(p_test))
    results_file = 'anom_detection.pkl'
    results = {}
    max_acc = {}
    for p in uports:
        results[p] = []
        max_acc[p] = 0

    results['name'] = 'som'

    if results['name'] == 'som':
        alpha = 101
        for k in range(2, 25):
            predictions = test_som(x_train, x_test, n_clusters=k, alpha=alpha)
            for a in range(alpha - 1):
                for p in uports:
                    acc, tpr, fpr = accuracy(np.array(y_test), predictions[:, a], ports=p_test, port=p)
                    results[p].append((acc, tpr, fpr, k, a + 1))  # acc, tpr, fpr, params
                    if acc > max_acc[p]:
                        max_acc[p] = acc
                        print(p, k, a + 1, acc, tpr, fpr)
    elif results['name'] == 'dbscan':
        pass

    for s in sorted(results[53], key=lambda x: x[0])[::-1][:5]:
        print(s)

    for s in sorted(results[80], key=lambda x: x[0])[::-1][:5]:
        print(s)

    with open(results_file, 'wb') as f:
        pickle.dump(results, f)
    
    """