import json
from time import time
from datetime import datetime
from subprocess import Popen, call
from flask import Flask, request, jsonify
from threading import Thread

app = Flask(__name__)

@app.route('/alerts', methods=['GET', 'DELETE'])
def get_alerts():
    if request.method == 'DELETE':
        open(alert_file,'w').close()
    return jsonify(log)

@app.route('/rules', methods=['GET', 'POST'])
def get_rules():
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        jdata = json.loads(data)
        with open(rule_file, 'w') as f:
            for rule in jdata['rules']:
                f.write(rule + '\n')
    with open(rule_file, 'r') as f:
        lines = f.readlines()
    rules = {"rules": []}
    for line in lines:
        if line.startswith('alert'):
            rules['rules'].append(line.strip())
    return jsonify(rules)

def load_alerts(alert_file):
    global log
    dt_now = datetime.now()
    while True:
        new_log = {'alerts':[]}
        with open(alert_file, 'r') as f:
            lines = f.readlines()
        for i in range(len(lines)):
            line = lines[i]
            title = line.strip()
            if title.startswith('[**]') and title.endswith('[**]'):
                try:
                    next_line = lines[i + 2].strip()
                    next_line_items = next_line.split(' ')
                    dt_timestamp = datetime.strptime(str(dt_now.year) + '/' + next_line_items[0],'%Y/%m/%d-%H:%M:%S.%f')
                    timestamp = str(dt_timestamp)
                    src_ip = next_line_items[1].split(':')[0]
                    if ':' in next_line_items[1]:
                        src_port = next_line_items[1].split(':')[1]
                    else:
                        src_port = ''
                    dst_ip = next_line_items[3].split(':')[0]
                    if ':' in next_line_items[3]:
                        dst_port = next_line_items[3].split(':')[1]
                    else:
                        dst_port = ''
                    proto = lines[i + 3].split(' ')[0]
                    new_log['alerts'].append([timestamp, src_ip, src_port, dst_ip, dst_port, proto])
                except Exception as e:
                    print(e)
        log = new_log

if __name__ == '__main__':

    # start ovs and default flows
    Popen(['service', 'openvswitch-switch', 'start'])
    Popen(['ifconfig', 'br-snort', 'up'])
    Popen(['ovs-ofctl', 'add-flow', 'br-snort', '"table=0, priority=1, action=output:LOCAL"'])

    # start snort
    Popen(['/usr/local/bin/snort', '-q', '-u', 'snort', '-g', 'snort', '-c', '/etc/snort/snort.conf', '-i', 'br-snort', '-K', 'ascii', '-k', 'notcp'])

    # logs
    alert_file = '/var/log/snort/alert'
    rule_file = '/etc/snort/rules/local.rules'
    log = {'alerts': []}

    # clean old alerts
    open(alert_file,'w').close()

    load_log_thread = Thread(target=load_alerts, args=(alert_file,))
    load_log_thread.setDaemon(True)
    load_log_thread.start()

    # start server
    app.run(host='0.0.0.0', port=8080)
