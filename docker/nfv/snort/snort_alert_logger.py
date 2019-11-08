import sys, os
from time import sleep
from subprocess import Popen, call, PIPE

if __name__ == '__main__':

    # add rules

    rule_file = '/etc/snort/rules/local.rules'
    rule_patterns = [
'alert udp any any -> {0} any (msg: "flow 0 content 0"; content: "|01 00|"; offset: 2; content: "|00 00 01 00 01|"; offset: 12; detection_filter: track by_src, count 10, seconds 1; sid:{1}; rev: 1;)',
        'alert udp {0} any -> any any (msg: "flow 1 content 0"; content: "|01 00|"; offset: 2; content: "|00 00 01 00 01|"; offset: 12; detection_filter: track by_dst, count 12, seconds 1; sid:{1}; rev: 1;)',
        'alert udp {0} any -> any any (msg: "flow 1 content 1"; content: "|01 00|"; offset: 2; content: "|00 00 1c 00 01|"; offset: 12; detection_filter: track by_dst, count 11, seconds 1; sid:{1}; rev: 1;)',
        'alert udp {0} any -> any any (msg: "flow 1 content 12";  detection_filter: track by_dst, count 43, seconds 1; sid:{1}; rev: 1;)',
        'alert udp {0} any -> any 53 (msg: "flow 2 content 0"; content: "|01 00|"; offset: 2; content: "|00 00 01 00 01|"; offset: 12; detection_filter: track by_dst, count 12, seconds 1; sid:{1}; rev: 1;)',
        'alert udp {0} any -> any 53 (msg: "flow 2 content 1"; content: "|01 00|"; offset: 2; content: "|00 00 1c 00 01|"; offset: 12; detection_filter: track by_dst, count 11, seconds 1; sid:{1}; rev: 1;)',
        'alert udp {0} any -> any 53 (msg: "flow 2 content 12";  detection_filter: track by_dst, count 43, seconds 1; sid:{1}; rev: 1;)',
        'alert udp any 53 -> {0} any (msg: "flow 3 content 0"; content: "|01 00|"; offset: 2; content: "|00 00 01 00 01|"; offset: 12; detection_filter: track by_src, count 10, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any any -> {0} 22 (msg: "flow 6 content 5"; content: "SSH-"; detection_filter: track by_src, count 4, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any any -> {0} 22 (msg: "flow 6 content 6"; flags: F; detection_filter: track by_src, count 5, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any any -> {0} 22 (msg: "flow 6 content 7"; flags: S; detection_filter: track by_src, count 4, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any any -> {0} 22 (msg: "flow 6 content 8"; flags: R; detection_filter: track by_src, count 6, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any any -> {0} 22 (msg: "flow 6 content 9"; flags: P; detection_filter: track by_src, count 36, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any any -> {0} 22 (msg: "flow 6 content 10"; flags: A; detection_filter: track by_src, count 47, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any any -> {0} 22 (msg: "flow 6 content 11";  detection_filter: track by_src, count 101, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} 22 -> any any (msg: "flow 7 content 5"; content: "SSH-"; detection_filter: track by_dst, count 4, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} 22 -> any any (msg: "flow 7 content 6"; flags: F; detection_filter: track by_dst, count 5, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} 22 -> any any (msg: "flow 7 content 7"; flags: S; detection_filter: track by_dst, count 4, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} 22 -> any any (msg: "flow 7 content 9"; flags: P; detection_filter: track by_dst, count 39, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} 22 -> any any (msg: "flow 7 content 10"; flags: A; detection_filter: track by_dst, count 58, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} 22 -> any any (msg: "flow 7 content 11";  detection_filter: track by_dst, count 115, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any any -> {0} any (msg: "flow 8 content 5"; content: "SSH-"; detection_filter: track by_src, count 4, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any any -> {0} any (msg: "flow 8 content 6"; flags: F; detection_filter: track by_src, count 10, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any any -> {0} any (msg: "flow 8 content 7"; flags: S; detection_filter: track by_src, count 11, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any any -> {0} any (msg: "flow 8 content 8"; flags: R; detection_filter: track by_src, count 6, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any any -> {0} any (msg: "flow 8 content 9"; flags: P; detection_filter: track by_src, count 52, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any any -> {0} any (msg: "flow 8 content 10"; flags: A; detection_filter: track by_src, count 88, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any any -> {0} any (msg: "flow 8 content 11";  detection_filter: track by_src, count 177, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} any -> any any (msg: "flow 9 content 2"; content: "get"; nocase; detection_filter: track by_dst, count 6, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} any -> any any (msg: "flow 9 content 3"; content: "post"; nocase; detection_filter: track by_dst, count 5, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} any -> any any (msg: "flow 9 content 5"; content: "SSH-"; detection_filter: track by_dst, count 4, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} any -> any any (msg: "flow 9 content 6"; flags: F; detection_filter: track by_dst, count 10, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} any -> any any (msg: "flow 9 content 7"; flags: S; detection_filter: track by_dst, count 10, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} any -> any any (msg: "flow 9 content 9"; flags: P; detection_filter: track by_dst, count 43, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} any -> any any (msg: "flow 9 content 10"; flags: A; detection_filter: track by_dst, count 89, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} any -> any any (msg: "flow 9 content 11";  detection_filter: track by_dst, count 187, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} any -> any 80 (msg: "flow 10 content 2"; content: "get"; nocase; detection_filter: track by_dst, count 6, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} any -> any 80 (msg: "flow 10 content 3"; content: "post"; nocase; detection_filter: track by_dst, count 5, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} any -> any 80 (msg: "flow 10 content 6"; flags: F; detection_filter: track by_dst, count 9, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} any -> any 80 (msg: "flow 10 content 7"; flags: S; detection_filter: track by_dst, count 9, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} any -> any 80 (msg: "flow 10 content 9"; flags: P; detection_filter: track by_dst, count 12, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} any -> any 80 (msg: "flow 10 content 10"; flags: A; detection_filter: track by_dst, count 51, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp {0} any -> any 80 (msg: "flow 10 content 11";  detection_filter: track by_dst, count 115, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any 80 -> {0} any (msg: "flow 11 content 6"; flags: F; detection_filter: track by_src, count 9, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any 80 -> {0} any (msg: "flow 11 content 7"; flags: S; detection_filter: track by_src, count 9, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any 80 -> {0} any (msg: "flow 11 content 9"; flags: P; detection_filter: track by_src, count 25, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any 80 -> {0} any (msg: "flow 11 content 10"; flags: A; detection_filter: track by_src, count 53, seconds 1; sid:{1}; rev: 1;)',
        'alert tcp any 80 -> {0} any (msg: "flow 11 content 11";  detection_filter: track by_src, count 105, seconds 1; sid:{1}; rev: 1;)'
    ]
    sid = 1
    mode = sys.argv[1]
    ips = sys.argv[2].split(',')
    if mode == 'custom':
        print(ips)
        lines = []
        for pattern in rule_patterns:
            for ip in ips:
                lines.append(pattern.format(ip, sid))
                sid += 1
        with open(rule_file, 'w') as f:
            for line in lines:
                f.write(line + '\n')

    # start ovs and default flows
    Popen(['service', 'openvswitch-switch', 'start']).wait()
    Popen(['ifconfig', 'br-snort', 'up']).wait()
    Popen(['ovs-ofctl', 'add-flow', 'br-snort', 'table=0,priority=1,action=output:LOCAL'])

    # start snort
    try:
        os.mkdir('/var/log/snort')
    except:
        pass
    Popen(['/usr/local/bin/snort', '-q', '-c', '/etc/snort/snort.conf', '-i', 'br-snort', '-K', 'ascii', '-k', 'notcp'])

    # clean old alerts
    alert_file = '/var/log/snort/alert'
    open(alert_file,'w').close()

    # sleep
    while True:
        sleep(1) 
