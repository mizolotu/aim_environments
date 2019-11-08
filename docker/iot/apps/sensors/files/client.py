import sys, requests, random, time, string, json
from threading import Thread
from subprocess import Popen, PIPE

def my_ip():
    p = Popen(['hostname', '-I'], stdout=PIPE)
    return p.stdout.read().decode('utf-8').strip()

def send_web_request(uri, timeout):
    global log
    try:
        if 'data' in uri:
            url = '{0}/data'.format(uri)
            data = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10*1024))
            requests.post(url, json={'ip': my_ip(), 'measurements': data}, timeout=timeout)
        elif 'unknown' in uri:
            url = '{0}/update/{1}'.format(uri,my_ip())
            requests.get(url, timeout=timeout)
        for sensor in log['sensors']:
            if sensor['ip'] == uri:
                sensor['n_connected'] += 1
                break
    except Exception as e:
        print(e)
        for sensor in log['sensors']:
            if sensor['ip'] == uri:
                sensor['n_failed'] += 1
                break

def poll_servers(servers, interval, log_file):
    while True:
        s_time = time.time()
        random.shuffle(servers)
        t_web = [Thread(target=send_web_request, args=(server, interval,)) for server in servers]
        for t in t_web:
            t.start()
        for t in t_web:
            t.join()
        with open(log_file, 'w') as f:
            json.dump(log, f) 
        time.sleep(interval - ((time.time() - s_time) % interval))

if __name__ == '__main__':
    p = Popen(['service', 'ssh', 'start'])
    servers = sys.argv[1].split(',')
    log = {'sensors': []}
    for device in servers:
        log['sensors'].append({'ip': device, 'n_connected': 0, 'n_failed': 0})
    log_file = '/var/log/sensor_activity'
    interval = 1
    t_http = Thread(target=poll_servers, args=(servers, interval, log_file,))
    t_http.start()
