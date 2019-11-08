from packet_capturer import *
from time import sleep
from sparse_som import *
from nltk import ngrams, FreqDist
from sklearn.metrics import euclidean_distances
from subprocess import Popen

import pickle
import numpy as np

def print_packet(headers, payloads):
    for h,p in zip(headers,payloads):
        print(h,p)

def mu_std_dist(centroid, sparse_vectors):
    d = [np.sqrt(np.sum((centroid - x.A[0])**2)) for x in sparse_vectors]
    mu = np.mean(d)
    si = np.std(d)
    return mu, si

def train_som(cd_fname='/opt/som_codebook.pkl', td_fname='/opt/2grams_short.pkl', n_clusters=24, alpha=97):
    try:
        with open(cd_fname, 'rb') as f:
            codebook = pickle.load(f)
            rad = pickle.load(f)
            ss = pickle.load(f)
            mas = pickle.load(f)
        n_clusters = codebook.shape[0]
    except Exception as e:
        with open(td_fname, 'rb') as f:
            x_train = pickle.load(f)
            x_test = pickle.load(f)
            ss = pickle.load(f)
            mas = pickle.load(f)
        _, N = x_train.shape
        som = Som(n_clusters, n_clusters, N, topology.HEXA)
        print(som.nrows, som.ncols, som.dim)
        som.codebook = np.random.rand(n_clusters, n_clusters, N).astype(som.codebook.dtype, copy=False)
        som.train(x_train)
        codebook = som.codebook
        bmus = som.bmus(x_train)
        rad = np.zeros((n_clusters, n_clusters))
        for i in range(n_clusters):
            for j in range(n_clusters):
                ids = np.where((bmus[:, 0] == i) & (bmus[:, 1] == j))[0]
                if len(ids) > 0:
                    vectors = [x_train[idx] for idx in ids]
                    mu, si = mu_std_dist(som.codebook[i, j, :], vectors)
                    rad[i, j] = mu + alpha * si
        with open(cd_fname, 'wb') as f:
            pickle.dump(som.codebook, f)
            pickle.dump(rad, f)
            pickle.dump(ss, f)
            pickle.dump(mas, f)
    return codebook, rad, ss, mas

def ngram(str, n):
    x = [int(item) for item in str.split(',')]
    freqs = np.zeros(256**n)
    v = 256 ** np.arange(n)[::-1]
    grams = ngrams(x, n)
    fd = FreqDist()
    fd.update(grams)
    for key in fd.keys():
        freqs[np.dot(key, v)] = fd[key]
    return freqs / (len(x) - n + 1)

def label_packets(headers, payloads, codebook, rad, ss, mas, fname):
    features = []
    flows = []
    for h, p in zip(headers, payloads):
        if len(p) > 0:
            flows.append(h)
            features.append(ngram(p, 2))
    if len(features) > 0:
        n = len(features)
        features = np.vstack(features)
        features = ss.transform(features)
        features = mas.transform(features)
        d = euclidean_distances(features, codebook)
        idx = np.argmin(d, 1)
        d_min = np.min(d, 1)
        alerts = []
        for i in range(n):
            if d_min[i] > rad[idx[i]]:
                alerts.append(flows[i])
        with open(fname, 'a') as f:
            for alert in alerts:
                f.write(','.join(alert) + '\n')

if __name__ == '__main__':

    # start ovs and default flows

    Popen(['service', 'openvswitch-switch', 'start']).wait()
    Popen(['ifconfig', 'ids', 'up']).wait()
    Popen(['ovs-ofctl', 'add-flow', 'ids', 'table=0,priority=1,action=output:LOCAL'])

    # get codebook and radias

    codebook, rad, ss, mas = train_som()
    n_clusters = codebook.shape[0]
    n_features = codebook.shape[2]
    codebook = codebook.reshape(n_clusters * n_clusters, n_features)
    codebook[np.isnan(codebook)] = 0
    rad = rad.reshape(n_clusters * n_clusters, 1)

    # start monitoring packets

    log_file = '/var/log/alerts'
    roll_time_threshold = 60
    open(log_file, 'w').close()

    cb = [
        {
            'func': label_packets,
            'args': (codebook, rad, ss, mas, log_file)
        }
    ]
    pm = PacketMonitor(cb)
    pm.start()
    while True:
        sleep(1)