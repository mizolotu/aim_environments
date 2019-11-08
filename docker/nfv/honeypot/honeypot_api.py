import netifaces, subprocess, sys, time
from flask import Flask, request, jsonify
from datetime import datetime
from threading import Thread

app = Flask(__name__)

@app.route("/bees", methods=['GET', 'DELETE'])
def get_bees():
    if request.method == 'DELETE':
        open(bee_file, 'w').close()
    return jsonify(log)

def parse_row(row):
    row = row.decode('utf-8').strip()
    parsed = []
    try:
        spl = row.split(' ')
        timestamp = ' '.join(spl[0:2])
        eth_proto = spl[2]
        if eth_proto == 'IP':
            src_ip_port = spl[3].split('.')
            src_ip = '.'.join(src_ip_port[0:4])
            src_port = '.'.join(src_ip_port[4:])
            dst_ip_port = spl[5][:-1].split('.')
            dst_ip = '.'.join(dst_ip_port[0:4])
            dst_port = '.'.join(dst_ip_port[4:])
            proto = spl[6]
            if proto.startswith('UDP'):
                type = 'udp'
            elif proto.startswith('ip-proto-6'):
                type = 'ip6'
            else:
                type = proto.lower()
            if type != 'ip6':
                size = spl[-1]
            else:
                size = '0'
        spl = row.split(' ')
        timestamp = ' '.join(spl[0:2])
        eth_proto = spl[2]
        if eth_proto == 'IP':
            src_ip_port = spl[3].split('.')
            src_ip = '.'.join(src_ip_port[0:4])
            src_port = '.'.join(src_ip_port[4:])
            dst_ip_port = spl[5][:-1].split('.')
            dst_ip = '.'.join(dst_ip_port[0:4])
            dst_port = '.'.join(dst_ip_port[4:])
            proto = spl[6]
            if proto.startswith('UDP'):
                type = 'udp'
            elif proto.startswith('ip-proto-6'):
                type = 'ip6'
            else:
                type = proto.lower()
            if type != 'ip6':
                size = spl[-1]
            else:
                size = '0'
            parsed = [timestamp, src_ip, src_port, dst_ip, dst_port, type]
        elif eth_proto.startswith('ARP'):
            src_port = ''
            dst_port = ''
            size = spl[-1]
            if spl[3] == 'Request':
                type = 'arp1'
                src_ip = spl[7][:-1]
                dst_ip = '255.255.255.255'
            elif spl[3] == 'Reply':
                type = 'arp2'
                src_ip = spl[4]
                dst_ip = '255.255.255.255'
            parsed = [timestamp, src_ip, src_port, dst_ip, dst_port, type]
        else:
            pass
    except Exception as e:
        print(e)
        t, v, tr = sys.exc_info()
        print(t,v,tr)
        pass
    return parsed

def log_packets(bee_file):
    args = ''
    for i in range(len(ignore_ip)):
        ip = ignore_ip[i]
        if i > 0:
            args += ' and'
        args += ' src not ' + ip + ' and dst not ' + ip
    for i in range(len(ignore_net)):
        net = ignore_net[i]
        args += ' and src net not ' + net + ' and dst net not ' + net
    if only_outgoing:
        args += ' and src ' + my_ip
    if ignore_ntp:
        args += ' and src port not 123 and dst port not 123'
    print(my_ip, args)
    p = subprocess.Popen(['tcpdump', '-lqSpnntttt', args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for row in iter(p.stdout.readline, 'b'):
        parsed = parse_row(row)
        if parsed:
            with open(bee_file, 'a') as log_file:
                log_file.write(','.join(parsed) + '\n')

def roll_logs(bee_file, time_thr):
    time.sleep(time_thr)
    start_time = time.time()
    while True:
        with open(bee_file, 'r') as f:
            lines = f.readlines()
        fresh_log = []
        for line in lines:
            try:
                spl = line.split(',')
                dt_timestamp = datetime.strptime(spl[0],'%Y-%m-%d %H:%M:%S.%f')
                timestamp = str(dt_timestamp)
                if (datetime.now() - dt_timestamp).total_seconds() < time_thr:
                    fresh_log.append(spl)
            except Exception as e:
                print(e)
        with open(bee_file, 'w') as f:
            for bee in fresh_log:
                f.write(','.join(bee))
        time.sleep(time_thr - (time.time() - start_time) % time_thr)

def load_logs(bee_file):
    global log
    while True:
        new_log = {'bees': []}
        with open(bee_file, 'r') as f:
            lines = f.readlines()
        for line in lines:
            spl = line.strip().split(',')
            new_log['bees'].append(spl)
        log = new_log

if __name__ == '__main__':

    # start ssh
    p = subprocess.Popen(['service', 'ssh', 'start'])

    # params
    only_outgoing = 1
    ignore_ip = ['8.8.8.8','8.8.4.4','192.168.80.1']
    ignore_net = ['192.168.103.0/24']
    ignore_ntp = 1
    my_ip = netifaces.ifaddresses('eth0')[2][0]['addr']
    bee_file = '/var/log/tcpdump_packets'
    log = {'bees':[]}
    roll_time_threshold = 60

    # clean old bees
    open(bee_file,'w').close()

    # start dumping packets
    dump_pkts_thread = Thread(target=log_packets, args=(bee_file,))
    dump_pkts_thread.setDaemon(True)
    dump_pkts_thread.start()

    # start rolling the logs
    roll_logs_thread = Thread(target=roll_logs, args=(bee_file,roll_time_threshold,))
    roll_logs_thread.setDaemon(True)
    roll_logs_thread.start()

    # staart loading the logs
    load_logs_thread = Thread(target=load_logs, args=(bee_file,))
    load_logs_thread.setDaemon(True)
    load_logs_thread.start()

    # start server
    app.run(host='0.0.0.0', port=8080)
