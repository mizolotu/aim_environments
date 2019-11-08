import time, requests
from threading import Thread as td

class StatusMonitor:

    def __init__(self, servers, prcs_cb, prcs_args=(), roll_interval=1):
        self.servers = servers
        self.process_callback = prcs_cb
        self.callback_args = prcs_args
        self.interval = roll_interval
        request_td = td(target=self.process_alerts)
        request_td.setDaemon(1)
        request_td.start()

    def process_alerts(self):
        s_time = time.time()
        while True:
            unique_ips = []
            for i in range(len(self.servers)):
                url = 'http://{0}:{1}/{2}'.format(
                    self.servers[i]['ip'],
                    self.servers[i]['port'],
                    self.servers[i]['url'],
                )
                try:
                    r = requests.get(url, timeout=self.interval)
                    sensors = r.json()[self.servers[i]['name']]
                    for sensor in sensors:
                        timestamp = sensor['last_seen']
                        if sensor['ip'] not in unique_ips and time.time() - timestamp < self.interval + 0.5:
                            unique_ips.append(sensor['ip'])
                except Exception as e:
                    pass
            self.process_callback(unique_ips, *self.callback_args)
            time.sleep(self.interval - ((time.time() - s_time) % self.interval))