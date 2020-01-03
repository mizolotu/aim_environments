import json, random, sys, logging

from flask import Flask, jsonify, request
from threading import Thread
from time import sleep, time
from itertools import cycle

from aim_environments import sensors

# Flask app and logging

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

### API methods ###

@app.route('/status')
def get_env_status():
    return jsonify(env.status)

@app.route('/connected_failed')
def get_n_connected_failed():
    return jsonify(env.n_connected_failed)

@app.route('/mirror_all')
def mirror_all_patterns():
    env.test_policy('mirror_all')
    return jsonify(env.status)

@app.route('/spoof_all')
def spoof_all_patterns():
    env.test_policy('spoof_all')
    return jsonify(env.status)

@app.route('/block_all')
def block_all_patterns():
    env.test_policy('block_all')
    return jsonify(env.status)

@app.route('/block_subnet/<string:subnet>')
def block_subnet_patterns(subnet):
    env.test_policy('block_subnet_' + subnet)
    return jsonify(env.status)

@app.route('/dns_gamma', methods=['GET', 'POST'])
def env_dns_gamma():
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        coeff = json.loads(data)
        env.gamma = coeff['gamma']
    g = env.gamma
    return jsonify(g)

@app.route('/score_coeff/<string:attack_name>', methods=['GET', 'POST'])
def env_score_coeff(attack_name):
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        coeff = json.loads(data)
        env.set_score_coeff(attack_name, coeff['a'], coeff['b'])
    a, b = env.get_score_coeff(attack_name)
    return jsonify(a, b)

@app.route('/info')
def get_info():
    return jsonify(env.info)

@app.route('/start_episode', methods=['POST'])
def start_episode():
    data = request.data.decode('utf-8')
    jdata = json.loads(data)
    attack_vector = jdata['attack']
    start_time = jdata['start']
    env.start_episode(attack_vector, start_time)
    return jsonify(env.info['episode_start_time'])

@app.route('/reset')
def reset_env():
    env.reset()
    return jsonify(env.status)

@app.route('/patterns')
def get_patterns():
    patterns = env.patterns['all']
    return jsonify(patterns)

@app.route('/state')
def get_state():
    flows, state_f, state_p, infected = env.get_state()
    return jsonify(flows, state_f, state_p, infected)

@app.route('/actions')
def get_actions():
    actions = []
    for action in env.actions:
        actions.append(action.__name__,)
    return(jsonify(actions, env.action_categories))

@app.route('/score')
def get_score():
    try:
        data = request.data.decode('utf-8')
        jdata = json.loads(data)
        flows = jdata['flows']
    except Exception as e:
        flows = None # env.current_flows
    scores, counts = env.calculate_score(flows)
    return jsonify(scores, counts)

@app.route('/action', methods=['GET', 'POST'])
def take_step():
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        jdata = json.loads(data)
        patterns = jdata['patterns']
        action_inds = jdata['action_inds']
        s_time = time()
        env.step(patterns, action_inds)
        # print(len(patterns), time() - s_time)
    return jsonify(env.action_logs.tolist())

@app.route('/test_action', methods=['GET', 'POST'])
def test_action():
    if request.method == 'POST':
        print(env.patterns)
        pattern = '6.192.168.103.101.192.168.104.101'
        #env.forward_through_snort_custom_action(pattern, 1, vnf_key='snort_custom', priority=20, table_id=5)
        env.forward_through_firewall_action(pattern, 1)
    return jsonify(env.action_logs.tolist())

### Auxiliary functions ###

def load_scenario(fpath):
    with open(fpath, 'r') as f:
        scenario = json.load(f)
    return scenario

def warmup_env(attacks, episode_duration, start_time, n_episodes=10, attack=None):
    attack_cycle = cycle(attacks)
    for e in range(int(n_episodes)):
        if attack is not None:
            if attack == 'random':
                attack_selected = random.choice(attacks)
            elif attack == 'cycle':
                attack_selected = next(attack_cycle)
            elif attack in attacks:
                attack_selected = attack
            print('\nEpisode: {0}, attack selected: {1}\n'.format(e + 1, attack_selected))
        else:
            attack_selected = None
        env.start_episode(attack_selected, start_time=start_time)
        sleep(start_time)
        while time() - env.info['episode_start_time'] < episode_duration:
            sleep(1)
        env.reset()

def test_env(attacks, episode_duration, start_time, policy=None, attack=None):
    attack_cycle = cycle(attacks)
    interval = 0.25
    while True:
        if attack is not None:
            if attack == 'random':
                attack_selected = random.choice(attacks)
            elif attack == 'cycle':
                attack_selected = next(attack_cycle)
            elif attack in attacks:
                attack_selected = attack
            print('\nAttack selected: {0}\n'.format(attack_selected))
        else:
            attack_selected = None
        env.start_episode(attack_selected, start_time)
        sleep(start_time)
        while time() - env.info['episode_start_time'] < episode_duration:
            if policy is not None:
                env.test_policy(policy)
            else:
                pass
            sleep(interval)
        env.reset()

if __name__ == '__main__':
    if 'small' in sys.argv:
        scenario_path = 'aim_environments/scenarios/sensors_small.json'
        print(scenario_path)
    else:
        scenario_path = 'aim_environments/scenarios/sensors.json'
    scenario = load_scenario(scenario_path)
    env = sensors.SensorsEnv()
    env.create_scenario(scenario)
    env.start_scenario()
    attacks = [
        'botnet_attack',
        'exfiltration_attack',
        'scan_attack',
        'exploit_attack',
        'slowloris_attack'
    ]
    if 'debug' in sys.argv:
        env.debug = True
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        test = Thread(target=test_env, args=(attacks, 30, 5, *sys.argv[2:]))
        test.setDaemon(True)
        test.start()
    elif len(sys.argv) > 1 and sys.argv[1] == 'warmup':
        env.log_packets = True
        warmup = Thread(target=warmup_env, args=(attacks, 30, 5, *sys.argv[2:]))
        warmup.setDaemon(True)
        warmup.start()
    app.run(host='0.0.0.0')
