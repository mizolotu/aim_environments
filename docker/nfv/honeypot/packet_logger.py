#!/usr/bin/python

import pwd, os, re, glob, time, subprocess, netifaces
from datetime import datetime as dt
from threading import Thread as td

LOG_FILE = '/var/log/tcpdump/packets'
my_ip = netifaces.ifaddresses('enp0s25')[2][0]['addr'] # change to ens3 in openstack's xenial instance

def parse_row(row):
    parsed = []
    try:
        spl = row.split(' ')
        timestamp = spl[0]
        size = spl[-1]
        eth_proto = spl[1]
        if eth_proto == 'IP':
            src_ip_port = spl[2].split('.')
            src_ip = '.'.join(src_ip_port[0:4])
            src_port = '.'.join(src_ip_port[4:])
            dst_ip_port = spl[4][:-1].split('.')
            dst_ip = '.'.join(dst_ip_port[0:4])
            dst_port = '.'.join(dst_ip_port[4:])
            proto = spl[5]
            if proto.startswith('UDP'):
                type = 'udp'
            else:
                type = proto.lower()
            parsed = [timestamp, src_ip, src_port, dst_ip, dst_port, type, size]
        elif eth_proto.startswith('ARP'):
            src_port = ''
            dst_port = ''
            if spl[2] == 'Request':
                type = 'arp1'
                src_ip = spl[6][:-1]
                dst_ip = spl[4]
            elif spl[2] == 'Reply':
                type = 'arp2'
                src_ip = spl[3]
                dst_ip = my_ip
            parsed = [timestamp, src_ip, src_port, dst_ip, dst_port, type, size]
        else:
            pass
    except Exception as e:
        print(e)
        pass
    return parsed

def log_packets():
    p = subprocess.Popen(['tcpdump', '-lqSpnn'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    with open(LOG_FILE, 'a') as log_file:
        for row in iter(p.stdout.readline, 'b'):
            parsed = parse_row(row)
            if parsed:
                for i in range(len(parsed)):
                    log_file.write(str(parsed[i]))
                    if i < len(parsed) - 1:
                        log_file.write(',')
                    #else:
                    #    log_file.write('\n')

def roll_logs(interval):
    starttime = time.time()
    while True:
        try:
            with open(LOG_FILE, 'r') as log_file:
                lines = log_file.readlines()
            with open(LOG_FILE, 'w') as log_file:
                for line in lines:
                    timestamp = dt.strptime(line.split(',')[0],'%Y-%m-%d %H:%M:%S.%f')
                    if (dt.now() - timestamp).total_seconds() < interval:
                        log_file.write(line)
        except:
            pass
        time.sleep(interval - ((time.time() - starttime) % interval))

if __name__ == '__main__':

    roll_interval = 60
    roll_td = td(target=roll_logs, args=(roll_interval,))
    roll_td.setDaemon(1)
    roll_td.start()

    log_packets()
