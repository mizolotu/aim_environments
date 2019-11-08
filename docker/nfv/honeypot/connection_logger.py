#!/usr/bin/python

import pwd, os, re, glob, time
from datetime import datetime as dt
from threading import Thread as td

LOG_FILE = '/var/log/netstat/connections'

PROTO = [
    "/proc/net/tcp",
    "/proc/net/udp"
    ]

STATE = {
        '01':'ESTABLISHED',
        '02':'SYN_SENT',
        '03':'SYN_RECV',
        '04':'FIN_WAIT1',
        '05':'FIN_WAIT2',
        '06':'TIME_WAIT',
        '07':'CLOSE',
        '08':'CLOSE_WAIT',
        '09':'LAST_ACK',
        '0A':'LISTEN',
        '0B':'CLOSING'
        }

def _load(proto):
    ''' Read the table of tcp connections & remove header  '''
    with open(proto,'r') as f:
        content = f.readlines()
        content.pop(0)
    return content

def _hex2dec(s):
    return str(int(s,16))

def _ip(s):
    ip = [(_hex2dec(s[6:8])),(_hex2dec(s[4:6])),(_hex2dec(s[2:4])),(_hex2dec(s[0:2]))]
    return '.'.join(ip)

def _remove_empty(array):
    return [x for x in array if x !='']

def _convert_ip_port(array):
    host,port = array.split(':')
    return _ip(host),_hex2dec(port)

def _get_pid_of_inode(inode):
    for item in glob.glob('/proc/[0-9]*/fd/[0-9]*'):
        try:
            if re.search(inode,os.readlink(item)):
                return item.split('/')[2]
        except:
            pass
    return None

def netstat():
    with open(LOG_FILE,'a') as log_file:
        for proto in PROTO:
            content=_load(proto)
            for line in content:
                timestamp = dt.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                line_array = _remove_empty(line.split(' '))     # Split lines and remove empty spaces.
                l_host,l_port = _convert_ip_port(line_array[1]) # Convert ipaddress and port from hex to decimal.
                r_host,r_port = _convert_ip_port(line_array[2])
                state = STATE[line_array[3]]
                uid = pwd.getpwuid(int(line_array[7]))[0]       # Get user from UID.
                inode = line_array[9]                           # Need the inode to get process pid.
                pid = _get_pid_of_inode(inode)                  # Get pid prom inode.
                try:                                               # try read the process name.
                    exe = os.readlink('/proc/'+pid+'/exe')
                except:
                    exe = None
                conn = [timestamp, uid, l_host+':'+l_port, r_host+':'+r_port, state, pid, exe, '\n']
                for i in range(len(conn)):
                    log_file.write(str(conn[i]))
                    if i < len(conn) - 2:
                        log_file.write(',')

def log_connections(interval):
    starttime = time.time()
    while True:
        netstat()
        time.sleep(interval - ((time.time() - starttime) % interval))

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

    log_interval = 0.5
    log_connections(log_interval)
