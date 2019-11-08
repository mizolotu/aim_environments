import json, time, random, string
from flask import Flask, request, jsonify
from threading import Thread

app = Flask(__name__)

@app.route("/")
def hello():
    return "Simple web server for sensor clients"

@app.route("/status")
def status():
    return jsonify(log)

@app.route("/data", methods=['POST'])
def receive_data():
    global log
    data = request.data.decode('utf-8')
    client_ip = json.loads(data)['ip']
    clients = [sensor['ip'] for sensor in log['sensors']]
    if client_ip not in clients:
        log['sensors'].append({'ip': client_ip, 'last_seen': time.time()})
    else:
        for sensor in log['sensors']:
            if sensor['ip'] == client_ip:
                sensor['last_seen'] = time.time()
    return 'OK'

@app.route("/update/<string:client_ip>", methods=['GET'])
def get_update(client_ip):
    global log
    data = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10*1024))
    clients = [sensor['ip'] for sensor in log['sensors']]
    if client_ip not in clients:
        log['sensors'].append({'ip': client_ip, 'last_seen': time.time()})
    else:
        for sensor in log['sensors']:
            if sensor['ip'] == client_ip:
                sensor['last_seen'] = time.time()
    return data

def roll_logs():
    global log
    while True:
        updated_log = {'sensors': []}
        for sensor in log['sensors']:
            if sensor['last_seen'] > time.time() - last_seen_thr:
                updated_log['sensors'].append(sensor)
        log = updated_log
        time.sleep(1)

if __name__ == '__main__':
    log = {'sensors': []}
    last_seen_thr = 5
    roll_logs_thread = Thread(target=roll_logs)
    roll_logs_thread.setDaemon(True)
    roll_logs_thread.start()
    app.run(host='0.0.0.0',port=80)
