import pickle, sys
import numpy as np

from packet_capturer import *
from sklearn.metrics.pairwise import euclidean_distances
from subprocess import Popen
from nltk import ngrams, FreqDist
from time import sleep

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

    # get codebook and radiuses

    cl_fname = '/opt/{0}.pkl'.format(sys.argv[1])
    port = int(sys.argv[2])
    with open(cl_fname, 'rb') as f:
        codebook = pickle.load(f)
        rad = pickle.load(f)
        ss = pickle.load(f)
        mas = pickle.load(f)

    # start monitoring packets

    log_file = '/var/log/alerts'
    roll_time_threshold = 60
    open(log_file, 'w').close()
    cb = [
        {
            'func': label_packets,
            'args': (codebook[port], rad[port], ss, mas, log_file)
        }
    ]
    pm = PacketMonitor(cb)
    pm.start()
    while True:
        sleep(1)