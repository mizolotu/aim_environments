import sys, paramiko, time, random, json
from threading import Thread

def poll_devices(hosts, timeout, log_file, ssh_port=22, username='ubuntu', password='ubuntu'):
    global log
    while True:
        for host in hosts:
            s_time = time.time()
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
                ssh.connect(host, port=ssh_port, username=username, password=password, timeout=1)
                _, stdout, _ = ssh.exec_command('hostname -I')
                ips = stdout.readline().split(' ')
                if host in ips:
                    for sensor in log['sensors']:
                        if sensor['ip'] == host:
                            sensor['n_connected'] += 1
                            break
                else:
                    for sensor in log['sensors']:
                        if sensor['ip'] == host:
                            sensor['n_failed'] += 1
                            break
                ssh.exec_command('ls /tmp')
                ssh.exec_command('touch /tmp/i_was_here')
            except Exception as e:
                for sensor in log['sensors']:
                    if sensor['ip'] == host:
                        sensor['n_failed'] += 1
                        break
                pass
            finally:
                ssh.close()
                with open(log_file, 'w') as f:
                    json.dump(log, f)
                time.sleep(timeout - ((time.time() - s_time) % timeout))

if __name__ == '__main__':
    devices = sys.argv[1].split(',')
    random.shuffle(devices)
    interval = 1
    log = {'sensors': []}
    for device in devices:
        log['sensors'].append({'ip': device, 'n_connected': 0, 'n_failed': 0})
    log_file = '/var/log/sensor_activity'
    t_ssh = Thread(target=poll_devices, args=(devices, interval, log_file,))
    t_ssh.start()
