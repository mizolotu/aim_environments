import subprocess, sys, time, json
from datetime import datetime
from threading import Thread
from scapy.all import *
from queue import Queue

def log_packet(pkt):
    if pkt.type == 2048:
        timestamp = str(datetime.now().timestamp())
        pkt_q.put((timestamp, pkt))

def create_filter():
    filter = ''
    for i in range(len(ignore_ip)):
        ip = ignore_ip[i]
        if i > 0:
            filter += ' and'
        filter += ' src not ' + ip + ' and dst not ' + ip
    for i in range(len(ignore_net)):
        net = ignore_net[i]
        filter += ' and src net not ' + net + ' and dst net not ' + net
    if only_outgoing: 
        filter += ' and src ('
        for i,my_ip in enumerate(my_ips):
            if i > 0:
                filter += ' or '
            filter += my_ip
        filter += ')'
    if ignore_ntp:
        filter += ' and src port not 123 and dst port not 123'
    return filter

def load_logs(log_file):
    while True:
        try:
            ts, pkt = pkt_q.get()
            print(ts, pkt)
            proto = str(pkt.proto)
            s_port = 0
            d_port = 0
            if proto in ['6','17']:
                s_port = pkt['IP'].sport
                d_port = pkt['IP'].dport
            parsed = [ts, pkt['IP'].src, str(s_port), pkt['IP'].dst, str(d_port), proto]
            with open(log_file, 'a') as f:
                 f.write(','.join(parsed) + '\n')
        except Exception as e:
            print(e)
            pass

if __name__ == '__main__':


    # start ovs
    ovs_ip = sys.argv[1] + '/24'
    ovs_mac = sys.argv[2]
    subprocess.Popen(['service', 'openvswitch-switch', 'start']).wait()
    subprocess.Popen(['ip', 'addr', 'add', ovs_ip, 'dev', 'br-hp']).wait()
    subprocess.Popen(['ip', 'link', 'set', 'dev', 'br-hp', 'up']).wait()    
    subprocess.Popen(['ovs-vsctl', 'set', 'bridge', 'br-hp', 'other-config:hwaddr=\"{0}\"'.format(ovs_mac)]).wait()

    # start ssh
    p = subprocess.Popen(['service', 'ssh', 'start'])

    # create filter
    p1 = subprocess.Popen(['hostname', '-I'], stdout=subprocess.PIPE)
    my_ips = p1.stdout.read().decode('utf-8').strip().split(' ')
    gw_ips = ['.'.join(my_ip.split('.')[:-1]) + '.1' for my_ip in my_ips]
    with open('/etc/resolv.conf', 'r') as f:
        lines = f.readlines()
    dns_ips = ['8.8.8.8', '8.8.4.4']
    only_outgoing = 1
    ignore_ip = gw_ips + dns_ips
    ignore_net = ['192.168.103.0/24']
    ignore_ntp = 1
    filter = create_filter()
    print(filter)

    # log params
    pkt_q = Queue()
    log_file = '/var/log/alerts'
    roll_time_threshold = 60

    # clean old bees
    open(log_file,'w').close()

    # start loading the logs
    load_logs_thread = Thread(target=load_logs, args=(log_file,))
    load_logs_thread.setDaemon(True)
    load_logs_thread.start()

    # start sniffer
    sniff(prn=log_packet, filter=filter, store=1)
