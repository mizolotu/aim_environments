import pickle
import numpy as np

def find_flow(v, flows):
    idx = []
    for i,flow in enumerate(flows):
        count = 0
        for v_i,item in zip(v, flow):
            if item == '*':
                count += 1
            elif item == v_i:
                count += 1
            else:
                break
        if count == len(v):
            idx.append(i)
    return idx

def find_similar_patterns(flow, patterns, degree = 3):
    idx = []
    for i, pattern in enumerate(patterns):
        count = 0
        for f_i,item in zip(flow, pattern):
            spl0 = f_i.split('.')
            spl1 = item.split('.')
            if spl0[:degree] == spl1[:degree]:
                if len(spl0) == degree + 1 and len(spl1) == degree + 1:
                    if spl0[degree] == '1' or spl1[degree] == '1':
                        if spl0[degree] == spl1[degree]:
                            count += 1
                        else:
                            break
                    else:
                        count += 1
                else:
                    count += 1
            else:
                break
        if count == len(flow):
            idx.append(i)
    return idx

def flow_to_snort_flow(flow):
    snort_flow = []
    proto = {
        '6': 'tcp',
        '17': 'udp'
    }
    for fi,f in enumerate(flow):
        if fi == 0:
            snort_flow.append(proto[f])
        elif len(f.split('.')) == 4 and f.split('.')[3] != '1':
            snort_flow.append('{0}')
        elif f == '*':
            snort_flow.append('any')
        else:
            snort_flow.append(f)
    return snort_flow

def get_ips(data, ip_prefix):
    ips = [
        item[1] for item in data if item[1].startswith(ip_prefix) and not item[1].endswith('.1')
    ] + [
        item[3] for item in data if item[3].startswith(ip_prefix) and not item[3].endswith('.1')
    ]
    unique_ips = list(set(ips))
    return unique_ips

def decode_tcp_flags_value(value):
    b = '{0:b}'.format(value)[::-1]
    positions = [i for i in range(len(b)) if b[i] == '1']
    return positions

def count_patterns(data, signatures, flow_patterns, payload_patterns, tw=1):
    n_counts = 13
    n = len(payload_patterns)
    n_flags = 5
    protocols = ['6', '17']
    n_protocols = len(protocols)
    counts = [[], []]
    t_start = data[0][0]
    t_step = t_start
    w_label = [0 for _ in range(len(flow_patterns))]
    for pkt_i in range(len(data)):
        pkt = data[pkt_i]
        label = label_pkt(pkt, signatures)
        ts = pkt[0]
        if ts >= t_step:
            w_label_last = list(w_label)
            w_label = [0 for _ in range(len(flow_patterns))]
            for c in counts:
                c.append(np.zeros((len(flow_patterns), n_counts)))
            t_step += tw
        if pkt_i % 10000 == 0:
            print('# seconds: {0}, {1}% completed'.format(len(counts[0]), float(pkt_i) / len(data) * 100))
        flow = [pkt[5]] + pkt[1:5]
        flag_positions = decode_tcp_flags_value(int(pkt[7]))
        proto = pkt[5]
        idx = find_flow(flow, flow_patterns)
        for i in idx:
            if label > 0:
                w_label[i] = 1
            l = max(w_label[i], w_label_last[i])
            for j,pp in enumerate(payload_patterns):
                if pp in pkt[-1]:
                    counts[l][-1][i, j] += 1
            for j in range(n_flags):
                if flag_positions.count(j):
                    counts[l][-1][i, n + j] += 1
            for j in range(n_protocols):
                if proto in protocols:
                    counts[l][-1][i, n + n_flags + protocols.index(proto)] += 1
    return counts

def find_attack_packets(data, signatures):
    look_before = 2
    look_after = 3
    pkts_checked = np.zeros(len(data), dtype=int)
    attack_pkts = np.zeros(len(data), dtype=int)
    t_line = [pkt[0] for pkt in data]
    data_flows = [','.join(pkt[1:6]) for pkt in data]
    for pkt_i, pkt in enumerate(data):
        if pkts_checked[pkt_i]:
            continue
        if pkt_i % 10000 == 0:
            print('{0} % completed'.format(float(pkt_i) / len(data) * 100))
        ts = pkt[0]
        if pkt[2] in ['53', '80'] or pkt[4] in ['53', '80']:
            label = label_pkt(pkt, signatures)
            if label > 0:
                flow = ','.join(pkt[1:6])
                r_flow = ','.join(pkt[3:5] + pkt[1:3] + pkt[5:6])
                print(flow, r_flow)
                inds = [
                    i for i in range(len(data))
                    if t_line[i] > ts - look_before and
                        t_line[i] < ts + look_after and
                        pkts_checked[i] == 0 and
                        (data_flows[i] == flow or data_flows[i] == r_flow)
                ]
                print(float(pkt_i)/len(data), len(inds))
                pkts_checked[inds] = 1
                attack_pkts[inds] = 1
    return attack_pkts

def label_pkt(pkt, signatures):
    label = 0
    for sig in signatures:
        n = len(sig)
        count = 0
        for key in sig.keys():
            if type(sig[key]) == list:
                c = sig[key][0]
                nc = sig[key][1]
                if c in pkt[key] and nc not in pkt[key]:
                    count += 1
                else:
                    break
            else:
                if sig[key] in pkt[key]:
                    count += 1
                else:
                    break
        if count == n:
            label = 1
            break
    return label

if __name__ == '__main__':

    # ips, protocols and ports

    ip_prefix = '192.168.103.'
    protocol_ports = {
        '6': [
            ['22','*'],
            ['80','*']
        ],
        '17': [
            ['*'],
            ['53','*']
        ]
    }

    # key words in content

    content_patterns = [
        '0,0,1,0,1',  # DNS A query
        '0,0,28,0,1',  # DNS AAAA query
        '71,69,84,32,47',  # HTTP GET
        '80,79,83,84,32,47',  # HTTP POST
        '80,85,84,32,47',  # HTTP PUT
        'SSH-'  # SSH
    ]

    # attack signatures

    attack_signatures = [
        {
            2: '53',
            5: '17',
            8: '4,101,118,105,108,3,106,121,117,2,102,105'
        },
        {
            4: '53',
            5: '17',
            8: '4,101,118,105,108,3,106,121,117,2,102,105'
        },
        {
            4: '80',
            5: '6',
            8: '45,88,58,32,88,45'
        },
        {
            4: '80',
            5: '6',
            8: ['71,69,84,32,47', '71,69,84,32,47,117,112,100,97,116,101']
        },
        {
            4: '80',
            5: '6',
            8: ['80,79,83,84,32,47', '80, 79, 83, 84, 32, 47, 100, 97, 116, 97']
        }
    ]

    # count content patterns in flow patterns and pickle them

    count_fnames = [
        'C:\\Users\\mikha\\Downloads\\counts_normal.pkl',
        'C:\\Users\\mikha\\Downloads\\counts_normal_and_attack.pkl'
    ]
    fnames = [
        'C:\\Users\\mikha\\Downloads\\packets1558623012.184722.csv',
        'C:\\Users\\mikha\\Downloads\\packets1558694632.468647.csv'
    ]
    for count_fname, fname in zip(count_fnames, fnames):
        try:
            with open(count_fname, 'rb') as f:
                flow_patterns = pickle.load(f)
                content_patterns = pickle.load(f)
                counts = pickle.load(f)
        except Exception as e:
            print(e)

        # read the file

            n_features = 9
            with open(fname, 'r') as f:
                lines = f.readlines()
            data = []
            count = 0
            for line in lines:
                spl = line.strip().split(',')
                v = [float(spl[0])] + spl[1:n_features - 1]
                p = ','.join(spl[n_features - 1:])
                if len(p) >= 2:
                    p = p[1:-1]
                v.append(p)
                data.append(v)
                count += 1
            print('# packets: {0}'.format(count))

            # generate flow patterns

            ips = get_ips(data, ip_prefix)
            flow_patterns = []
            for ip in ips:
                for key in protocol_ports.keys():
                    incoming_ports = protocol_ports[key][0]
                    outgoing_ports = protocol_ports[key][1]
                    for port in incoming_ports:
                        flow_patterns.append((key, '*', '*', ip, port))
                        flow_patterns.append((key, ip, port, '*', '*'))
                    for port in outgoing_ports:
                        flow_patterns.append((key, ip, '*', '*', port))
                        flow_patterns.append((key, '*', port, ip, '*'))

            counts = count_patterns(data, attack_signatures, flow_patterns, content_patterns)
            with open(count_fname,'wb') as f:
                pickle.dump(flow_patterns, f)
                pickle.dump(content_patterns, f)
                pickle.dump(counts, f)

    # load both files

    counts = []
    for cfname in count_fnames:
        with open(cfname, 'rb') as f:
            flow_patterns = pickle.load(f)
            content_patterns = pickle.load(f)
            cnts = pickle.load(f)
        counts.append(cnts)

    # generate snort rules

    rules = []
    rule_template = '        \'alert {0} {1} {2} -> {3} {4} (msg: "{5}"; {6} detection_filter: track {7}, count {8}, seconds 1; sid:{{1}}; rev: 1;)\','
    content = [
        'content: "|01 00|"; offset: 2; content: "|00 00 01 00 01|"; offset: 12;',
        'content: "|01 00|"; offset: 2; content: "|00 00 1c 00 01|"; offset: 12;',
        'content: "get"; nocase;',
        'content: "post"; nocase;',
        'content: "put"; nocase;',
        'content: "SSH-";',
        'flags: F;',
        'flags: S;',
        'flags: R;',
        'flags: P;',
        'flags: A;',
        '',
        ''
    ]
    protocols = ['tcp', 'udp']
    n_protocols = len(protocols)

    sh = counts[0][0][0].shape
    ruled_patterns = [0 for _ in range(sh[0])]
    for i in range(sh[0]):
        if ruled_patterns[i] == 0:
            flow_pattern = flow_patterns[i]
            flow_template = flow_to_snort_flow(flow_pattern)
            if flow_template[1] == 'any' and flow_template[3] != 'any':
                track = 'by_src'
            elif flow_template[3] == 'any' and flow_template[1] != 'any':
                track = 'by_dst'
            idx = find_similar_patterns(flow_pattern, flow_patterns)
            nz0 = []
            nz1 = []
            for id in idx:
                ruled_patterns[id] = 1
            for j in range(sh[1]):
                nz0 = []
                nz1 = []
                for k in idx:
                    nz0.extend([c[i, j] for c in counts[0][0] if c[i, j] > 0])
                    nz1.extend([c[i, j] for c in counts[1][1] if c[i, j] > 0])
                if nz0 != []:
                    mx = np.max(nz0)
                else:
                    mx = None
                if nz1 != []:
                    mn = np.min(nz1)
                else:
                    mn = None
                if mx is not None and mn is not None:
                    rules.append(
                        rule_template.format(
                            flow_template[0],
                            flow_template[1],
                            flow_template[2],
                            flow_template[3],
                            flow_template[4],
                            'flow ' + str(i) + ' content ' + str(j),
                            content[j],
                            track,
                            max(int(mx + 1), mn),
                        )
                    )
                    print(rules[-1])