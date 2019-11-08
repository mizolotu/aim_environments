import copy, csv, docker, iptc, os, pcap, random, requests, signal, tarfile
import numpy as np

from collections import deque
from datetime import datetime
from itertools import cycle
from random import shuffle
from threading import Thread, Timer
from time import time, sleep

from environments.common.odl_utils import *
from environments.common.ovs_utils import *
from environments.common.net_utils import *
from environments.common.dir_utils import *
from environments.common.flow_mon import FlowMonitor

class SensorsEnv:

    def __init__(self):

        self.docker_cli = docker.from_env()
        self.container_base = {
            'name': '',
            'image': '',
            'cmd': '',
            'network': '',
            'dns': [],
            'restart': {'Name': 'on-failure'},
            'cap': '',
            'detach': False,
            'tty': False
        }
        self.container_volumes_dir = '/tmp/container_volumes'
        self.vnf_categories = [
            'snort_community',
            'snort_custom',
            'som53',
            'som80',
            'honeypot'
        ]
        self.action_categories = [
            'snort_community',
            'snort_custom',
            'som53',
            'som80',
            'honeypot',
            'drop_connections',
            #'block_incoming',
            #'block_outgoing'
        ]
        self.time_threshold = 3
        self.update_interval = 0.25
        self.time_window = 5.0
        self.debug = False
        self.log_packets = False
        t_now = time()
        self.pkt_log_file = '/tmp/packets_{0}.csv'.format(t_now)
        self.gym_log_file = '/tmp/episodes_{0}.csv'.format(t_now)
        with open(self.gym_log_file, 'w') as f:
            f.close()
        if self.log_packets:
            with open(self.pkt_log_file, 'w') as f:
                f.close()
        self.status = 'INITIALIZED'

    def create_scenario(self, scenario):

        # create volume directory or clean it if it exists already

        if (os.path.isdir(self.container_volumes_dir)):
            clean_directory(self.container_volumes_dir)
        else:
            os.mkdir(self.container_volumes_dir)

        # categories, keys and roles

        categories = []
        keys = []
        roles = []
        for category in ['vnf', 'app', 'attacker']:
            for key in scenario[category].keys():
                roles.append(scenario[category][key])
                keys.append(key)
                categories.append(category)

        # networks

        ovs = clean_ovs_ports()
        self.ovs_nets = scenario['ovs_nets']
        self.networks = self.prepare_networks(roles, nets=scenario['nets'])
        self.create_networks(self.networks)
        self.clean_networks(self.networks.keys())

        # containers

        self.containers, self.device_ips = self.prepare_containers(roles, keys, categories)
        for category in self.containers.keys():
            for key in self.containers[category]:
                self.create_containers(self.containers[category][key])

        # start and configure nfv containers

        for category in ['vnf']:
            containers = []
            for key in self.containers[category]:
                containers.extend(self.containers[category][key])
            self.start_containers(containers)
            self.connect_containers_to_networks(containers)
        for key in self.containers['vnf'].keys():
            self.execute_commands(self.containers['vnf'][key])

        # connect switches

        self.connect_switches_to_each_other()
        self.sdn = scenario['sdn']
        self.connect_switches_to_controller(self.sdn['switches'], self.sdn['ip'], self.sdn['port'])
        switches = []
        for net in self.ovs_nets:
            switch_names = [switch['name'] for switch in net['switches']]
            net_switches = [(key,ovs[key]) for key in ovs.keys() if key in switch_names]
            for switch in net_switches:
                switches.append((switch))
        vnf_containers = []
        for key in self.containers['vnf'].keys():
            vnf_containers.extend(self.containers['vnf'][key])
        self.connect_switches_to_vnfs(switches, vnf_containers)

        # add switch generators to ovs_nets

        for net in self.ovs_nets:
            net['switch_generator'] = cycle(net['switches'])
            for switch in net['switches']:
                port_names = ovs[switch['name']].keys()
                ports = [ovs[switch['name']][key] for key in port_names]
                mac = [port['mac'] for port in ports if port['type'] == 'internal'][0]
                zero_patches = [port['port'] for port,port_name in zip(ports,port_names) if port['type'] == 'patch' and 'zero' in port_name]
                switch['mac'] = mac
                switch['id'] = 'openflow:{0}'.format(str(int(''.join(mac.split(':')), 16)))
                if len(zero_patches) > 0:
                    switch['zero'] = zero_patches[0]
                else:
                    switch['zero'] = None

        # start app and attacker containers

        for category in ['app', 'attacker']:
            containers = []
            for key in self.containers[category]:
                containers.extend(self.containers[category][key])
            self.start_containers(containers)
            self.connect_containers_to_networks(containers)

        # add ofport tables to ovs_nets

        sw_names = {}
        for net in self.ovs_nets:
            for switch in net['switches']:
                sw_names[switch['id']] = switch['name']
        ips = []
        ovs_net_ips = []
        ovs_net_sws = []
        ovs_net_ofports = []
        ovs_net_names = [net['name'] for net in self.ovs_nets]
        for category in ['app', 'attacker']:
            for key in self.containers[category].keys():
                for container in self.containers[category][key]:
                    ips.append(container['ip'])
                    if container['network'] in ovs_net_names:
                        ovs_net_ips.append(container['ip'])
                        ovs_net_sws.append(sw_names[container['switch']])
                        ovs_net_ofports.append(container['ofport'])
        for nw in self.networks.values():
            gw_ip = nw['gateway']
            ips.append(gw_ip)
            if nw['driver'] == 'ovs':
                net_idx = ovs_net_names.index(nw['name'])
                gw_switch = self.ovs_nets[net_idx]['gw_switch']
                ovs_net_ips.append(gw_ip)
                ovs_net_sws.append(gw_switch)
                ovs_net_ofports.append('LOCAL')
        for net in self.ovs_nets:
            net['switch_generator'] = cycle(net['switches'])
            for switch in net['switches']:
                ifaces = ovs[switch['name']].keys()
                switch['ofports'] = [get_iface_ofport(iface) for iface in ifaces if iface != switch['name']]
                switch['ofports'].append('LOCAL')
                ofport_table = {}
                sw_ips = [ip for ip,sw in zip(ovs_net_ips,ovs_net_sws) if sw == switch['name']]
                sw_ofports = [ofport for ofport, sw in zip(ovs_net_ofports, ovs_net_sws) if sw == switch['name']]
                for src in ips:
                    for dst in ips:
                        if dst != src:
                            key = '{0}.{1}'.format(src, dst)
                            if src in sw_ips:
                                src_port = sw_ofports[sw_ips.index(src)]
                                if dst in sw_ips:
                                    dst_port = sw_ofports[sw_ips.index(dst)]
                                elif dst in ovs_net_ips:
                                    idx = ovs_net_ips.index(dst)
                                    sw_name = ovs_net_sws[idx]
                                    spl_src = switch['name'].split('_')
                                    spl_dst = sw_name.split('_')
                                    tunnel_name = spl_src[0][0:3] + spl_src[1] + spl_dst[0][0:3] + spl_dst[1]
                                    dst_port = get_iface_ofport(tunnel_name)
                                else:
                                    dst_port = 'LOCAL'
                                if src_port != dst_port:
                                    ofport_table[key] = (src_port, dst_port)
                            elif dst in sw_ips:
                                dst_port = sw_ofports[sw_ips.index(dst)]
                                if src in sw_ips:
                                    src_port = sw_ofports[sw_ips.index(src)]
                                elif src in ovs_net_ips:
                                    idx = ovs_net_ips.index(src)
                                    sw_name = ovs_net_sws[idx]
                                    spl_dst = switch['name'].split('_')
                                    spl_src = sw_name.split('_')
                                    tunnel_name = spl_dst[0][0:3] + spl_dst[1] + spl_src[0][0:3] + spl_src[1]
                                    src_port = get_iface_ofport(tunnel_name)
                                else:
                                    src_port = 'LOCAL'
                                if src_port != dst_port:
                                    ofport_table[key] = (src_port, dst_port)
                switch['ofport_table'] = ofport_table
                if self.debug:
                    print(ofport_table)

        # push initial flows to switches

        for net in self.ovs_nets:
            switches_without_controller = [switch['name'] for switch in net['switches'] if switch['name'] not in self.sdn['switches']]
            for switch in switches_without_controller:
                push_output_normal(switch)

        controller = {
            'cfg': Nodes,
            'ip': self.sdn['ip'],
            'switches': self.sdn['switches'],
            'port': self.sdn['access']['api_port'],
            'username': self.sdn['access']['api_credentials']['username'],
            'password': self.sdn['access']['api_credentials']['password']
        }
        for net in self.ovs_nets:
            for switch in net['switches']:
                if switch['name'] in self.sdn['switches']:
                    switch['cfg'] = controller['cfg'](controller['ip'], controller['port'], controller['username'], controller['password'])
                    init_flow_tables(switch['cfg'], switch['id'], switch['zero'], priority=0)
                    switch['flows'] = []

        # add redirect-to-local flow to the zero bridge

        Popen(['ovs-ofctl', 'add-flow', 'zero', 'table=0,priority=1,action=output:LOCAL'])

        # extract application ports and protocols

        self.current_flows = []
        self.patterns = []
        self.reverse_patterns = []
        self.device_idx = []
        self.app_ports = ['53']  # assume that DNS traffic is always there
        self.app_protocols = ['17']  # assume that DNS traffic is always there
        for category in ['app', 'attacker']:
            for key in scenario[category].keys():
                if 'port' in scenario[category][key].keys():
                    port = str(scenario[category][key]['port'])
                    if port not in self.app_ports:
                        self.app_ports.append(port)
                if 'proto' in scenario[category][key].keys():
                    proto = str(scenario[category][key]['proto'])
                    if proto not in self.app_protocols:
                        self.app_protocols.append(proto)
        self.app_protocols.sort()
        self.app_ports.sort()
        self.n_pkt_features = 7 + len(self.app_ports) + len(self.app_protocols)
        self.n_flow_features = 11 + len(self.app_ports) + len(self.app_protocols)

        # shuffle dns tables

        server_names = []
        server_categories = []
        ips = []
        for category in ['app', 'attacker']:
            for key in scenario[category].keys():
                if scenario[category][key]['network'] == 'server' and 'names' in scenario[category][key].keys():
                    for i,name in enumerate(scenario[category][key]['names']):
                        server_names.append(name)
                        server_categories.append((category, key, i))
                    for container in self.containers[category][key]:
                        ips.append(container['ip'])
        self.resolv = {
            'local_file': scenario['app']['device']['dns']['local_file'],
            'z_file': scenario['app']['device']['dns']['z_file'],
            'rz_file': scenario['app']['device']['dns']['rz_file'],
            'names': server_names,
            'categories': server_categories
        }
        shuffle(ips)
        cc_ip = ''
        ip_generator = iter(ips)
        for category, key, idx in self.resolv['categories']:
            ip = next(ip_generator)
            self.containers[category][key][idx]['ip'] = ip
            print(category,key,idx,ip,self.containers[category][key][idx]['ip'])
            if category == 'attacker' and 'cc' in key:
                cc_ip = ip
        self.resolv['ips'] = ips
        self.update_dns_tables(cc_ip)

        # start application

        for key in ['admin', 'device']:
            self.execute_commands(self.containers['app'][key])

        # remove honeypot and server isolation rules

        for category in ['honeypot', 'server']:
            try:
                network_obj = self.docker_cli.networks.get(category)
                bridge_id = 'br-{0}'.format(network_obj.id[:12])
                rule = iptc.Rule()
                rule.in_interface = bridge_id
                rule.out_interface = '!' + bridge_id
                rule.create_target('DOCKER-ISOLATION-STAGE-2')
                chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), 'DOCKER-ISOLATION-STAGE-1')
                chain.delete_rule(rule)
            except:
                pass

        self.status = 'CREATED'

    def prepare_networks(self, roles, nets):
        networks = {}
        for net in nets:
            n = sum([role['number'] for role in roles if role['network'] == net['name']])
            network = {
                'name': net['name'],
                'driver': 'bridge',
                'subnet': subnet(net['start'], net['mask']),
                'gateway': gateway(net['start']),
                'ip_generator': iter(ip_range(net['start'], n))
            }
            ovs_net_names = [ovs_net['name'] for ovs_net in self.ovs_nets]
            if net['name'] in ovs_net_names:
                network['driver'] = 'ovs'
                network['switches'] = [switch['name'] for switch in self.ovs_nets[ovs_net_names.index(net['name'])]['switches']]
                network['gw_switch'] = self.ovs_nets[ovs_net_names.index(net['name'])]['gw_switch']
            networks[net['name']] = network
        return networks

    def prepare_containers(self, roles, keys, categories):
        containers = {}
        device_ips = []
        server_names = []
        for category in list(set(categories)):
            containers[category] = {}
        for role,key,category in zip(roles,keys,categories):
            base = dict(self.container_base)
            base['network'] = role['network']
            base['netmask'] = self.networks[role['network']]['subnet'].split('/')[-1]
            base['image'] = role['image']
            if key == 'snort_community':
                base['detach'] = True
                base['tty'] = True
                base['cap'] = 'NET_ADMIN'
                base['cmd'] = "/bin/bash"
                base['exec_cmd'] = "python3 /usr/local/bin/snort_alert_logger.py community"
            elif key == 'snort_custom':
                base['detach'] = True
                base['tty'] = True
                base['cap'] = 'NET_ADMIN'
                base['cmd'] = "/bin/bash"
                base['exec_cmd'] = "python3 /usr/local/bin/snort_alert_logger.py custom"
            elif key == 'som53':
                base['detach'] = True
                base['tty'] = True
                base['cap'] = 'NET_ADMIN'
                base['cmd'] = "/bin/bash"
                base['exec_cmd'] = "python3 /usr/local/bin/anomaly_detector.py som 53"
            elif key == 'som80':
                base['detach'] = True
                base['tty'] = True
                base['cap'] = 'NET_ADMIN'
                base['cmd'] = "/bin/bash"
                base['exec_cmd'] = "python3 /usr/local/bin/anomaly_detector.py som 80"
            elif key == 'honeypot':
                base['detach'] = True
                base['tty'] = True
                base['cap'] = 'NET_ADMIN'
                base['cmd'] = "/bin/bash"
                base['ovs_ip'] = role['ovs_ip']
                base['ovs_mac'] = encode_ip_as_mac(role['ovs_ip'].split('.'))[0]
                base['exec_cmd'] = "python3 /usr/local/bin/honey_bee_logger.py {0} {1}".format(base['ovs_ip'], base['ovs_mac'])
                base['potted'] = []
                base['nat_map'] = {'src_dst': [], 'octet': []}
            elif key == 'server':
                base['cmd'] = "python3 /usr/local/bin/server.py"
                server_names.extend(role['names'])
            elif key == 'admin':
                base['detach'] = True
                base['tty'] = True
                base['cmd'] = "/bin/bash"
                base['exec_cmd'] = "python3 /usr/local/bin/admin.py"
            elif key == 'device':
                base['detach'] = True
                base['tty'] = True
                base['cmd'] = "/bin/bash"
                base['exec_cmd'] = "python3 /usr/local/bin/client.py"
                base['dns'] = role['dns']['ips']
            elif key == 'botnet_cc':
                base['cmd'] = "python3 /usr/local/bin/botnet_cc.py"
            elif key == 'malware_server':
                base['cmd'] = "python3 /usr/local/bin/malware_server.py"
            role_containers = []
            for i in range(role['number']):
                container = copy.deepcopy(base)
                name = '{0}_{1}'.format(key, i + 1)
                container['name'] = name
                container['ip'] = next(self.networks[container['network']]['ip_generator'])
                if key == 'device':
                    device_ips.append(container['ip'])
                container['volume'] = '{0}/{1}'.format(self.container_volumes_dir, name)
                role_containers.append(container)
            containers[category][key] = role_containers

        # add command args for snorts, admins and devices

        snort_containers = []
        for key in containers['vnf'].keys():
            if key.startswith('snort'):
                snort_containers.extend(containers['vnf'][key])
        for container in snort_containers + containers['app']['admin']:
            container['exec_cmd'] += ' {0}'.format(','.join(device_ips))
        for container in containers['app']['device']:
            container['exec_cmd'] += ' {0}'.format(','.join(server_names))

        return containers, device_ips

    def create_networks(self, networks):
        for key in networks.keys():
            network = networks[key]
            if network['driver'] == 'bridge':
                subnet = network['subnet']
                gateway = network['gateway']
                does_network_exist = False
                try:
                    network_obj = self.docker_cli.networks.get(network['name'])
                    if {'Gateway': gateway, 'Subnet': subnet} in network_obj.attrs['IPAM']['Config']:
                        does_network_exist = True
                    else:
                        for container_obj in network_obj.containers:
                            try:
                                network_obj.disconnect(container_obj)
                            except Exception as e:
                                if self.debug:
                                    print(e)
                        network_obj.remove()
                except Exception as e:
                    pass
                if not does_network_exist:
                    ipam_pool = docker.types.IPAMPool(
                        subnet = network['subnet'],
                        gateway = network['gateway']
                    )
                    ipam_config = docker.types.IPAMConfig(
                        pool_configs = [ipam_pool]
                    )
                    self.docker_cli.networks.create(network['name'], driver='bridge', ipam=ipam_config, check_duplicate=True)
            elif network['driver'] == 'ovs':
                gw = network['gateway']
                mask = network['subnet'].split('/')[-1]
                Popen(['ip', 'addr', 'add', gw + '/' + mask, 'dev', network['gw_switch']]).wait()
                Popen(['ip', 'link', 'set', 'dev', network['gw_switch'], 'up']).wait()
                postrouting_chain = iptc.Chain(iptc.Table(iptc.Table.NAT), 'POSTROUTING')
                rule = iptc.Rule()
                rule.src = network['subnet']
                rule.create_target('MASQUERADE')
                self.add_rule_to_iptables(rule, postrouting_chain)
                forward_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), 'FORWARD')
                for switch in network['switches']:
                    rule = iptc.Rule()
                    match = iptc.Match(rule, 'conntrack')
                    match.ctstate = "RELATED,ESTABLISHED"
                    rule.add_match(match)
                    rule.out_interface = switch
                    rule.create_target('ACCEPT')
                    self.add_rule_to_iptables(rule, forward_chain)
                    rule = iptc.Rule()
                    rule.out_interface = switch
                    rule.create_target('DOCKER')
                    self.add_rule_to_iptables(rule, forward_chain)
                    rule = iptc.Rule()
                    rule.in_interface = switch
                    rule.out_interface = '!' + switch
                    rule.create_target('ACCEPT')
                    self.add_rule_to_iptables(rule, forward_chain)
                    rule = iptc.Rule()
                    rule.in_interface = switch
                    rule.out_interface = switch
                    rule.create_target('ACCEPT')
                    self.add_rule_to_iptables(rule, forward_chain)

    def add_rule_to_iptables(self, rule, chain):
        deleted = False
        while not deleted:
            try:
                chain.delete_rule(rule)
            except:
                deleted = True
        chain.insert_rule(rule)

    def connect_switches_to_each_other(self):
        switch_pairs = []
        for net in self.ovs_nets:
            for switch in net['switches']:
                switch_1 = switch['name']
                for switch_2 in switch['connect_to']:
                    if (switch_1, switch_2) not in switch_pairs and (switch_2, switch_1) not in switch_pairs:
                        switch_pairs.append((switch_1, switch_2))
        for switch_1, switch_2 in switch_pairs:
            veth_1 = '{0}{1}{2}{3}'.format(switch_1[0:3], switch_1[-1], switch_2[0:3], switch_2[-1])
            veth_2 = '{0}{1}{2}{3}'.format(switch_2[0:3], switch_2[-1], switch_1[0:3], switch_1[-1])
            Popen(['ip', 'link', 'add', veth_1, 'type', 'veth', 'peer', 'name', veth_2]).wait()
            Popen(['ovs-vsctl', 'add-port', switch_1, veth_1]).wait()
            Popen(['ip', 'link', 'set', 'dev', veth_1, 'up']).wait()
            Popen(['ovs-vsctl', 'add-port', switch_2, veth_2]).wait()
            Popen(['ip', 'link', 'set', 'dev', veth_2, 'up']).wait()

    def connect_switches_to_controller(self, switches, controller_ip, port=6653):
        controller_socket = 'tcp:{0}:{1}'.format(controller_ip, port)
        for switch in switches:
            Popen(['ovs-vsctl', 'set-controller', switch, controller_socket])

    def connect_switches_to_vnfs(self, switches, vnf_containers):
        vnf_names = [container['name'] for container in vnf_containers]
        vnf_ips = [container['ip'] for container in vnf_containers]
        for switch_key,switch in switches:
            for key in switch.keys():
                if key in vnf_names:
                    ip = vnf_ips[vnf_names.index(key)]
                    Popen(['ovs-vsctl', 'set', 'interface', key, 'options:remote_ip=' + ip])
                    gw = '.'.join(ip.split('.')[:-1]) + '.1'
                    container_obj = self.docker_cli.containers.get(key)
                    container_obj.exec_run('ovs-vsctl set interface vxlan1 options:remote_ip={0}'.format(gw))
        for net in self.ovs_nets:
            for net_switch in net['switches']:
                net_switch['vnf'] = []
                for switch_key,switch in switches:
                    print(net_switch['name'], switch_key)
                    if net_switch['name'] == switch_key:
                        for port_key in switch.keys():
                            print(port_key)
                            if port_key in vnf_names:
                                ofport = switch[port_key]['port']
                                net_switch['vnf'].append((ofport, port_key))

    def create_containers(self, containers):
        for container in containers:
            try:
                container_obj = self.docker_cli.containers.get(container['name'])
                container_obj.stop(timeout=0)
                container_obj.remove()
            except Exception as e:
                if self.debug:
                    print(e)
            finally:
                if container['network'] in [ovs_net['name'] for ovs_net in self.ovs_nets]:
                    network = 'none'
                else:
                    network = container['network']
                self.docker_cli.containers.create(
                    name=container['name'],
                    image=container['image'],
                    command=container['cmd'],
                    network=network,
                    dns=container['dns'],
                    cap_add=container['cap'],
                    restart_policy=container['restart'],
                    detach=container['detach'],
                    tty=container['tty'],
                    log_config=docker.types.LogConfig(type=docker.types.LogConfig.types.JSON, config={"max-size": "10M"}),
                    volumes={
                        '{0}/log'.format(container['volume']): {
                            'bind': '/var/log',
                            'mode': 'rw'
                        },
                        '{0}/tmp'.format(container['volume']): {
                            'bind': '/tmp',
                            'mode': 'rw'
                        }
                    }
                )

    def clean_networks(self, network_keys):
        ovs_net_names = [ovs_net['name'] for ovs_net in self.ovs_nets]
        for network_key in network_keys:
            if network_key not in ovs_net_names:
                network_obj = self.docker_cli.networks.get(network_key)
                for container_obj in network_obj.containers:
                    try:
                        network_obj.disconnect(container_obj)
                    except Exception as e:
                        if self.debug:
                            print(e)
                        pass
            else:
                netns_dir = '/var/run/netns'
                if (os.path.isdir(netns_dir)):
                    clean_directory(netns_dir)
                else:
                    os.mkdir(netns_dir)

    def connect_containers_to_networks(self, containers):
        ovs_net_names = [ovs_net['name'] for ovs_net in self.ovs_nets]
        for container in containers:
            container_obj = self.docker_cli.containers.get(container['name'])
            if container['network'] in ovs_net_names:
                ovs_net_idx = ovs_net_names.index(container['network'])
                switch_selected = next(self.ovs_nets[ovs_net_idx]['switch_generator'])
                mac_str, mac_hex = encode_ip_as_mac(container['ip'].split('.'))
                ip = '{0}/{1}'.format(container['ip'], container['netmask'])
                gw = '{0}.1'.format('.'.join(container['ip'].split('.')[:-1]))
                pid = str(container_obj.attrs['State']['Pid'])
                veth_h = '{0}_h'.format(container['name'])
                veth_c = '{0}_c'.format(container['name'])
                switch_name = switch_selected['name']
                Popen(['ip', 'link', 'delete', veth_h]).wait()
                Popen(['ip', 'link', 'add', veth_h, 'type', 'veth', 'peer', 'name', veth_c]).wait()
                Popen(['ovs-vsctl', 'add-port', switch_name, veth_h]).wait()
                proc_net = '/proc/{0}/ns/net'.format(pid)
                run_net = '/var/run/netns/{0}'.format(pid)
                Popen(['ln', '-s', proc_net, run_net]).wait()
                Popen(['ip', 'link', 'set', veth_c, 'netns', pid]).wait()
                Popen(['ip', 'netns', 'exec', pid, 'ip', 'link', 'set', 'dev', veth_c, 'name', 'eth0']).wait()
                Popen(['ip', 'netns', 'exec', pid, 'ip', 'link', 'set', 'dev', 'eth0', 'up']).wait()
                Popen(['ip', 'netns', 'exec', pid, 'ip', 'link', 'set', 'eth0', 'address', mac_str]).wait()
                Popen(['ip', 'netns', 'exec', pid, 'ip', 'addr', 'add', ip, 'dev', 'eth0']).wait()
                Popen(['ip', 'netns', 'exec', pid, 'ip', 'route', 'add', 'default', 'via', gw]).wait()
                Popen(['ip', 'link', 'set', veth_h, 'up']).wait()
                container['switch'] = switch_selected['id']
                container['ofport'] = get_iface_ofport(veth_h)
            else:
                network_obj = self.docker_cli.networks.get(container['network'])
                try:
                    network_obj.disconnect(container_obj)
                except:
                    pass
                finally:
                    network_obj.connect(container_obj, ipv4_address=container['ip'])

    def start_containers(self, containers):
        for container in containers:
            self.docker_cli.containers.get(container['name']).start()

    def execute_commands(self, containers):
        for container in containers:
            if 'exec_cmd' in container.keys():
                container_obj = self.docker_cli.containers.get(container['name'])
                cmd = container['exec_cmd'].split(' ')[:2]
                ps_aux = container_obj.top(ps_args='aux')
                ps_list = [p[-1].split(' ')[:2] for p in ps_aux['Processes']]
                if cmd not in ps_list:
                    print(container['exec_cmd'])
                    container_obj.exec_run(container['exec_cmd'], detach=True, tty=True)

    def kill_process(self, container, prcs_prefix):
        container_obj = self.docker_cli.containers.get(container['name'])
        ps_aux = container_obj.top(ps_args='aux')
        ps_list = [(int(p[1]), ' '.join(p[-1].split(' ')[:2])) for p in ps_aux['Processes']]
        for pid, prcs in ps_list:
            if prcs.startswith(prcs_prefix):
                try:
                    os.kill(pid, signal.SIGKILL)
                except:
                    pass

    def clean_directory_on_containers(self, containers, directory):
        for container in containers:
            container_obj = self.docker_cli.containers.get(container['name'])
            code, output = container_obj.exec_run('ls {0}'.format(directory))
            files = output.decode('utf-8').strip().split('\n')
            for file in files:
                container_obj.exec_run('rm {0}/{1}'.format(directory, file))

    def restart_containers(self, containers, timeout=0):
        for container in containers:
            self.docker_cli.containers.get(container['name']).restart(timeout=timeout)

    def update_dns_tables(self, cc_ip, local=['honeypot']):
        local_lines = [
            'zone "server.jyu.fi" {{type master; file "{0}"; allow-transfer {{127.0.0.1;}};}};'.format(self.resolv['z_file']),
            'zone "evil.jyu.fi" IN {{ type forward; forward only; forwarders {{ {0}; }}; }};'.format(cc_ip),
            'zone "104.168.192.in-addr.arpa" { type master; file "/etc/bind/db.104"; allow-transfer { 127.0.0.1; }; };',
            'zone "200.168.192.in-addr.arpa" {{ type master; file "{0}"; allow-transfer {{ 127.0.0.1; }}; }};'.format(self.resolv['rz_file']),
        ]
        with open(self.resolv['local_file'], 'w') as f:
            for line in local_lines:
                f.write(line + '\n')
        rz_lines = [
            '$TTL 604800',
            '@ IN SOA localhost. root.localhost. (2 604800 86400 2419200 604800)',
            '@ IN NS localhost.',
        ]
        z_lines = rz_lines + [
            '@ IN A 127.0.0.1',
            '@ IN AAAA ::1'
        ]
        with open(self.resolv['z_file'], 'w') as f:
            for line in z_lines:
                f.write(line + '\n')
        with open(self.resolv['rz_file'], 'w') as f:
            for line in rz_lines:
                f.write(line + '\n')
        ips = self.resolv['ips']
        names = [name.split('.')[0] for name in self.resolv['names']]
        names_to_ips = ['{0} IN A {1}'.format(name, ip) for ip, name in zip(ips, names)]
        with open(self.resolv['z_file'], 'a') as f:
            for line in names_to_ips:
                f.write(line + '\n')
        last_octets = [ip.split('.')[-1] for ip in ips]
        ips_to_names = ['{0} IN PTR {1}'.format(octet, name) for octet, name in zip(last_octets, self.resolv['names'])]
        with open(self.resolv['rz_file'], 'a') as f:
            for line in ips_to_names:
                f.write(line + '\n')
        Popen(['service', 'bind9', 'restart']).wait()

        ips_names = ['{0}\t{1}'.format(ip,name) for ip,name in zip(ips,self.resolv['names'])]
        remote_path = '/etc/hosts'
        local_path = '/tmp/hosts'
        for category in self.containers.keys():
            for key in self.containers[category]:
                if key in local:
                    for container in self.containers[category][key]:
                        container_obj = self.docker_cli.containers.get(container['name'])
                        code, output = container_obj.exec_run('cat {0}'.format(remote_path))
                        lines = output.decode('utf-8').split('\n')
                        pair_found = [0 for ip in ips]
                        for i,line in enumerate(lines):
                            ip = line.split('\t')[0]
                            if ip in ips:
                                idx = ips.index(ip)
                                name = self.resolv['names'][idx]
                                pair_found[idx] = 1
                                lines[i] = '{0}\t{1}'.format(ip, name)
                        for i,idx in enumerate(pair_found):
                            if idx == 0:
                                ip_name = ips_names[i]
                                lines.append(ip_name)
                        with open(local_path, 'w') as f:
                            for line in lines:
                                f.write(line + '\n')
                        self.copy_to_container(local_path, container_obj, local_path)
                        container_obj.exec_run('cp {0} {1}'.format(local_path, remote_path)) # because docker treats /etc/hosts differently

    def copy_to_container(self, local_path, container_obj, remote_path):
        os.chdir(os.path.dirname(local_path))
        srcname = os.path.basename(local_path)
        tar = tarfile.open(local_path + '.tar', mode='w')
        try:
            tar.add(srcname)
        finally:
            tar.close()
        data = open(local_path + '.tar', 'rb').read()
        container_obj.put_archive(os.path.dirname(remote_path), data)

    def start_scenario(self):

        self.infected = []
        self.attack_flows = {'a': [], 'b': []}

        # define env log

        self.log = {
            'attack': '',
            'graph': {},
            'score': np.nan,
            'debug': {
                'episode': 0,
                'episode_start_time': 0,
                'flow_queue_size': 0,
                'packets_dropped': 0,
                'attack_flows' : []
            }
        }

        # state

        self.lock = False

        self.state_window_size = int(self.time_window / self.update_interval)
        self.n_vnf_features = len(self.vnf_categories)
        self.n_action_categories = len(self.action_categories)
        self.state_feature_vector_size = self.n_flow_features + 2*self.n_vnf_features + self.n_action_categories

        self.vnf_logs = np.zeros((0, self.n_vnf_features))
        self.sum_vnf_logs = np.zeros((0, self.n_vnf_features))
        self.action_logs = np.zeros((0, self.n_action_categories))
        self.frames = deque(maxlen=self.state_window_size)
        for i in range(self.state_window_size):
            self.frames.append((np.zeros((0, self.n_pkt_features)), [], np.zeros((0, self.n_flow_features)), []))
        self.state_p = [np.zeros((0, self.n_pkt_features)) for _ in range(self.state_window_size)]
        self.state_f = [np.zeros((0, self.state_feature_vector_size)) for _ in range(self.state_window_size)]

        # start monitor

        flow_cbs = [
            {'func': self.update_state, 'args': ()}
        ]
        vnf_cbs = [
            {'func': self.check_snort_alerts, 'args': ()},
            {'func': self.check_anomaly_alerts, 'args': ()},
            {'func': self.check_honeypot_alerts, 'args': ()}
        ]
        flow_monitor = FlowMonitor(flow_cbs, vnf_cbs)
        flow_monitor.start()

        # actions

        self.actions = [
            lambda *args: None,
            self.pass_action,
            self.mirror_to_snort_community_action,
            self.mirror_to_snort_custom_action,
            self.mirror_to_som53_action,
            self.mirror_to_som80_action,
            self.redirect_to_honeypot_action,
            self.drop_connections_action,
            #self.block_source_action,
            #self.block_destination_action
        ]

        self.n_actions = len(self.actions)
        self.n_not_logged_actions = self.n_actions - self.n_action_categories
        self.mirror_actions = [i for i in np.arange(self.n_actions) if 'mirror' in self.actions[i].__name__]
        self.n_mirror_actions = len(self.mirror_actions)
        self.redirect_actions = [i for i in np.arange(self.n_actions) if 'redirect' in self.actions[i].__name__]
        self.n_redirect_actions = len(self.redirect_actions)
        self.drop_actions = [i for i in np.arange(self.n_actions) if 'drop' in self.actions[i].__name__]
        self.n_drop_actions = len(self.drop_actions)
        self.block_actions = [i for i in np.arange(self.n_actions) if 'block' in self.actions[i].__name__]
        self.n_block_actions = len(self.block_actions)

        # reward

        self.n_connected_failed = []
        self.score_coeff = {
            'botnet_attack': (0, 0),
            'exfiltration_attack': (0, 0),
            'scan_attack': (0, 0),
            'exploit_attack': (0, 0),
            'slowloris_attack': (0, 0)
        }
        self.score_a = 0
        self.score_b = 0
        self.gamma = 1
        self.detection_bonus = 0.25
        self.n_connected_failed_delta = []
        self.count_frames = [np.zeros(5) for _ in range(self.state_window_size)]
        self.reward_frames = [np.zeros((0, 1)) for _ in range(self.state_window_size)]

        # change permissions for tmp directories of containers just in case

        for category in self.containers.keys():
            for key in self.containers[category].keys():
                for container in self.containers[category][key]:
                    tmp_path = '{0}/tmp'.format(container['volume'])
                    os.chmod(tmp_path, 0o777)

        # define network graph and start updating its values

        self.attack_containers = []
        self.define_network_graph()
        self.monitor_network_graph()

        # define dns subnets and subnets that require to be resolved

        self.dns_subnets = []
        for container in self.containers['app']['device']:
            for dns_ip in container['dns']:
                subnet_ip = '.'.join(dns_ip.split('.')[0:3])
                if subnet_ip not in self.dns_subnets:
                    self.dns_subnets.append(subnet_ip)
        self.to_be_resolved_subnets = []
        for ip in self.resolv['ips']:
            subnet_ip = '.'.join(ip.split('.')[0:3])
            if subnet_ip not in self.to_be_resolved_subnets:
                self.to_be_resolved_subnets.append(subnet_ip)

        self.status = 'READY'

    def step(self, patterns, action_inds):
        for pattern,action_idx in zip(patterns, action_inds):
            pattern_idx = self.patterns.index(pattern)
            action = self.actions[action_idx]
            if action_idx == 0:
                action()
            elif action_idx == 1:
                action(pattern)
            else:
                if action_idx in self.mirror_actions or action_idx in self.redirect_actions:
                    self.before_forward_action(pattern, action_idx)
                idx = action_idx - self.n_not_logged_actions
                action_type = 1 - self.action_logs[pattern_idx, idx]
                if action_type == 1:
                    action(pattern, action_type)
                    self.action_logs[pattern_idx, idx] = action_type
            if self.debug:
                device_ip = '.'.join(pattern.split('.')[1:5])
                if (pattern in self.attack_flows['a']) or (pattern in self.attack_flows['b'] and device_ip in self.infected):
                    if idx >= 0:
                        if action_type == 1:
                            direction = 'IN'
                        else:
                            direction = 'OUT'
                    print('{0}, {1}: {2}'.format(pattern, action.__name__, direction)) 

    def update_state(self, packets, q_size):
        while True:
            if self.lock:
                pass
            else:
                self.lock = True
                t_start = time()
                self.log['debug']['flow_queue_size'] = q_size
                self.log['debug']['packets_dropped'] += q_size
                packet_features, flows, flow_features, flow_labels = self.calculate_features(packets)
                self.frames.append((packet_features, flows, flow_features, flow_labels))  # here we append a new frame and delete the oldest one
                for f in flows:
                    if f not in self.patterns:
                        self.patterns.append(f)
                        self.vnf_logs = np.vstack([self.vnf_logs, np.zeros((1, self.n_vnf_features))])
                        self.sum_vnf_logs = np.vstack([self.sum_vnf_logs, np.zeros((1, self.n_vnf_features))])
                        self.action_logs = np.vstack([self.action_logs, np.zeros((1, self.n_action_categories))])
                current_flows = []
                for frame in self.frames:
                    for f in frame[1]:
                        if f not in current_flows:
                            current_flows.append(f)
                if self.debug:
                    print('Number of flows = {0}'.format(len(current_flows)))
                    print('Number of packets = {0}'.format([len(x) for x in self.state_p]))
                state_size = len(current_flows)
                state_f = []
                state_p = []
                reward_frames = []
                count_frames = []
                for i in range(len(self.state_f)):
                    packet_features = self.frames[i][0]
                    flows = self.frames[i][1]
                    flow_features = self.frames[i][2]
                    flow_labels = self.frames[i][3]
                    state_frame = np.zeros((state_size, self.state_feature_vector_size))
                    reward_frame = np.zeros(state_size)
                    count_frame = np.zeros(5)
                    for flow, flow_feature_vector, flow_label in zip(flows, flow_features, flow_labels):
                        idx = flow_follows_pattern(flow, current_flows)
                        idx_ = flow_follows_pattern(flow, self.patterns)
                        state_frame[idx, :] = np.hstack([
                        flow_feature_vector,
                            self.vnf_logs[idx_, :],
                            self.sum_vnf_logs[idx_, :],
                            self.action_logs[idx_, :]
                        ])
                        if np.any(self.sum_vnf_logs[idx_, :] > 0):
                            gain = self.detection_bonus
                        else:
                            gain = 0
                        device_ip = '.'.join(flow.split('.')[1:5])
                        number_of_replies = flow_label[2]
                        if flow in self.attack_flows['a']:
                            coeff = - self.score_a * (1 - gain)
                            count_frame[0] += number_of_replies
                        elif flow in self.attack_flows['b'] and device_ip in self.infected:
                            coeff = - self.score_b * (1 - gain)
                            count_frame[1] += number_of_replies
                        else:
                            remote_subnet = '.'.join(flow.split('.')[5:8])
                            if remote_subnet in self.dns_subnets and flow_label[0] == 2: # i.e. DNS
                                coeff = self.gamma
                                count_frame[2] += number_of_replies
                            elif remote_subnet in self.to_be_resolved_subnets:
                                coeff = 1
                                count_frame[3] += number_of_replies
                            else:
                                coeff = 1
                                count_frame[4] += number_of_replies
                        reward_frame[idx] = coeff * number_of_replies
                    state_f.append(state_frame)
                    state_p.append(packet_features)
                    reward_frames.append(reward_frame)
                    count_frames.append(count_frame)
                self.current_flows = list(current_flows)
                self.state_p = list(state_p)
                self.state_f = list(state_f)
                self.reward_frames = list(reward_frames)
                self.count_frames = list(count_frames)
                self.lock = False
                if self.debug:
                    print('{0} seconds spent to update state'.format(time() - t_start))
                break

    def calculate_features(self, packets):
        tic = time()
        flows = []
        flow_labels = []
        ports = []
        recognized_ports = []
        recognized_protocols = []
        sizes = []
        flags = []
        packet_features = np.zeros((len(packets), self.n_pkt_features))
        for p_i,packet in enumerate(packets):

            # packet features for the context

            packet_features[p_i, 0] = packet[0] - time() + 1
            packet_features[p_i, 1] = packet[6]
            pkt_flags = decode_tcp_flags_value(packet[7])
            packet_features[p_i, 2] = pkt_flags.count(0)
            packet_features[p_i, 3] = pkt_flags.count(1)
            packet_features[p_i, 4] = pkt_flags.count(2)
            packet_features[p_i, 5] = pkt_flags.count(3)
            packet_features[p_i, 6] = pkt_flags.count(4)
            if packet[5] in self.app_protocols:
                packet_features[p_i, 6 + self.app_protocols.index(packet[5])] = 1
            if packet[2] in self.app_ports:
                packet_features[p_i, 6 + len(self.app_protocols) + self.app_ports.index(packet[2])] = 1
            if packet[4] in self.app_ports:
                packet_features[p_i, 6 + len(self.app_protocols) + self.app_ports.index(packet[4])] = 1

            # flows and flow features

            idx = -1
            if packet[1] in self.device_ips:
                flow = src_dst_pattern(packet[5], packet[1], packet[3])
            elif packet[3] in self.device_ips:
                flow = src_dst_pattern(packet[5], packet[3], packet[1])
            else:
                continue 
                print(packet[0:5])
            idx = flow_follows_pattern(flow, flows)
            if idx < 0:
                flows.append(flow)
                flow_labels.append([0, 0, 0]) # 0 - app port index, # of requests, # of replies
                ports.append([])
                recognized_ports.append(np.zeros(len(self.app_ports)))
                recognized_protocols.append(np.zeros(len(self.app_protocols)))
                sizes.append([])
                flags.append([])
                idx = len(flows) - 1
            if packet[2] in self.app_ports:
                app_port_idx = self.app_ports.index(packet[2])
                recognized_ports[idx][app_port_idx] = 1
                flow_labels[idx][0] = app_port_idx + 1   # reply: ssh = 1, dns = 2, http = 3
                flow_labels[idx][2] += 1
                ports[idx].append(packet[4])
            if packet[4] in self.app_ports:
                app_port_idx = self.app_ports.index(packet[4])
                recognized_ports[idx][app_port_idx] = 1
                flow_labels[idx][0] = app_port_idx + 1   # request: ssh = 1, dns = 2, http = 3
                flow_labels[idx][1] += 1
                ports[idx].append(packet[2])
            if packet[5] in self.app_protocols:
                recognized_protocols[idx][self.app_protocols.index(packet[5])] = 1
            sizes[idx].append(packet[6])
            flags[idx] += pkt_flags
        flow_features = np.zeros((len(flows), self.n_flow_features))
        if len(flows) > 0:
            flow_features[:, 0] = [len(list(set(x))) for x in ports]  # number of unique ports, i.e. number of connections
            flow_features[:, 1] = [x[1] for x in flow_labels]  # number of requests
            flow_features[:, 2] = [x[2] for x in flow_labels]  # number of replies
            flow_features[:, 3] = [np.min(x) for x in sizes]  # min packet size
            flow_features[:, 4] = [np.max(x) for x in sizes]  # max packet size
            flow_features[:, 5] = [np.mean(x) for x in sizes]  # average packet size
            flow_features[:, 6] = [x.count(0) for x in flags]  # number of FIN flags
            flow_features[:, 7] = [x.count(1) for x in flags]  # number of SYN flags
            flow_features[:, 8] = [x.count(2) for x in flags]  # number of RST flags
            flow_features[:, 9] = [x.count(3) for x in flags]  # number of PSH flags
            flow_features[:, 10] = [x.count(4) for x in flags]  # number of ACK flags
            for i in range(len(self.app_protocols)):
                flow_features[:, 11 + i] = [x[i] for x in recognized_protocols] # recognized protocols
            for i in range(len(self.app_ports)):
                flow_features[:, 11 + len(self.app_protocols) + i] = [x[i] for x in recognized_ports] # recognized ports
        if self.log_packets:
            with open(self.pkt_log_file, 'a') as f:
                writer = csv.writer(f)
                writer.writerows(packets)
        toc = time()
        if self.debug:
            print('Spent to calculate features: {0}'.format(toc - tic))
        return packet_features, flows, flow_features, flow_labels

    def check_snort_alerts(self, alert_file = 'log/snort/alert'):
        dt_now = datetime.now()
        for key in self.containers['vnf'].keys():
            if key.startswith('snort'):
                alerts = []
                for container in self.containers['vnf'][key]:
                    try:
                        with open('{0}/{1}'.format(container['volume'], alert_file), 'r') as f:
                            lines = f.readlines()
                            for i in range(len(lines)):
                                line = lines[i]
                                title = line.strip()
                                if title.startswith('[**]') and title.endswith('[**]'):
                                    try:
                                        next_line = lines[i + 2].strip()
                                        next_line_items = next_line.split(' ')
                                        dt_timestamp = datetime.strptime(str(dt_now.year) + '/' + next_line_items[0], '%Y/%m/%d-%H:%M:%S.%f')
                                        timestamp = str(dt_timestamp.timestamp())
                                        src_ip = next_line_items[1].split(':')[0]
                                        if ':' in next_line_items[1]:
                                            src_port = next_line_items[1].split(':')[1]
                                        else:
                                            src_port = '0'
                                        dst_ip = next_line_items[3].split(':')[0]
                                        if ':' in next_line_items[3]:
                                            dst_port = next_line_items[3].split(':')[1]
                                        else:
                                            dst_port = '0'
                                        proto = protocol_number(lines[i + 3].split(' ')[0])
                                        alerts.append([timestamp, src_ip, src_port, dst_ip, dst_port, proto])
                                    except Exception as e:
                                        if self.debug:
                                            print(e)
                    except Exception as e:
                        pass
                #if alerts: print(alerts)
                self.update_vnf_logs(alerts, key)

    def check_anomaly_alerts(self, alert_file = 'log/alerts'):
        for key in self.containers['vnf'].keys():
            if key.startswith('anomaly'):
                alerts = []
                for container in self.containers['vnf'][key]:
                    try:
                        with open('{0}/{1}'.format(container['volume'], alert_file), 'r') as f:
                            lines = f.readlines()
                            for line in lines:
                                spl = line.strip().split(',')
                                if len(spl) >= 6:
                                    ts = spl[0]
                                    remote = spl[2:]
                                    for src in container['potted']:
                                        alerts.append([ts] + [src] + remote)
                    except Exception as e:
                        pass
                #if alerts: print(alerts)
                self.update_vnf_logs(alerts, key)

    def check_honeypot_alerts(self, alert_file = 'log/alerts'):
        alerts = []
        containers = self.containers['vnf']['honeypot']
        for container in containers:
            try:
                with open('{0}/{1}'.format(container['volume'], alert_file), 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        spl = line.strip().split(',')
                        if len(spl) >= 6:
                            ts = spl[0]
                            remote = spl[2:]
                            for src in container['potted']:
                                alerts.append([ts] + [src] + remote)
            except:
                pass
        if self.debug:
            if alerts:
                print(alerts)
        if alerts: print(alerts)
        self.update_vnf_logs(alerts, key='honeypot')

    def update_vnf_logs(self, alerts, key):
        n_patterns = len(self.vnf_logs)
        log_features = np.zeros(n_patterns)
        current_features = np.zeros(n_patterns)
        t_now = time()
        for alert in alerts:
            if alert[1] in self.device_ips:
                flow = src_dst_pattern(alert[5], alert[1], alert[3])
            elif alert[3] in self.device_ips:
                flow = src_dst_pattern(alert[5], alert[3], alert[1])
            idx = flow_follows_pattern(flow, self.patterns)
            if idx >= 0:
                t_alert = float(alert[0])
                log_features[idx] += 1
                if t_now - t_alert <= self.time_threshold:
                    current_features[idx] += 1
        i = self.vnf_categories.index(key)
        if n_patterns > 0:
            self.vnf_logs[:,i] = current_features
            self.sum_vnf_logs[:,i] = log_features

    def prepare_for_action(self, pattern, vnf_key=None):
        proto, src, dst = src_dst_ips(pattern)
        if src in self.device_ips:
            device_idx = self.device_ips.index(src)
        elif dst in self.device_ips:
            device_idx = self.device_ips.index(dst)
        switch_id = self.containers['app']['device'][device_idx]['switch']
        tunnel = None
        switch_found = False
        for net in self.ovs_nets:
            if switch_found:
                break
            for switch in net['switches']:
                if switch['id'] == switch_id:
                    for i in range(len(switch['vnf'])):
                        port, name = switch['vnf'][i]
                        if vnf_key is not None:
                            for container in self.containers['vnf'][vnf_key]:
                                if container['name'] == name:
                                    tunnel = port
                                    break
                    cfg = switch['cfg']
                    switch_found = True
                    break

        return cfg, switch, tunnel

    def before_forward_action(self, pattern, action_idx): # includes mirror and redirect actions
        pattern_idx = self.patterns.index(pattern)
        idx = action_idx - self.n_not_logged_actions
        inds_to_switch_off = [i for i in np.arange(len(self.patterns)) if i != pattern_idx and self.action_logs[i, idx] == 1]
        action = self.actions[action_idx]
        for i in inds_to_switch_off:
            action(self.patterns[i], action_type=0)
            self.action_logs[i, idx] = 0

    def mirror_to_snort_community_action(self, pattern, action_type, vnf_key='snort_community', priority=10, table_id=1):
        cfg, switch, tunnel = self.prepare_for_action(pattern, vnf_key)
        # print(pattern, action_type, cfg, switch['id'], tunnel)
        if action_type == 1:
            pushed_flows = mirror_to_tunnel(cfg, pattern, switch['id'], table_id, priority, tunnel)
            switch['flows'].extend(pushed_flows)
        elif action_type == 0:
            removed_flows = unmirror_from_tunnel(cfg, pattern, switch['id'], table_id)
            for flow in removed_flows:
                while flow in switch['flows']:
                    switch['flows'].remove(flow)
        self.update_action_logs(pattern, key=vnf_key, value=action_type)

    def mirror_to_snort_custom_action(self, pattern, action_type, vnf_key='snort_custom', priority=10, table_id=2):
        cfg, switch, tunnel = self.prepare_for_action(pattern, vnf_key)
        if action_type == 1:
            pushed_flows = mirror_to_tunnel(cfg, pattern, switch['id'], table_id, priority, tunnel)
            switch['flows'].extend(pushed_flows)
        elif action_type == 0:
            removed_flows = unmirror_from_tunnel(cfg, pattern, switch['id'], table_id)
            for flow in removed_flows:
                while flow in switch['flows']:
                    switch['flows'].remove(flow)
        self.update_action_logs(pattern, key=vnf_key, value=action_type)

    def mirror_to_som53_action(self, pattern, action_type, vnf_key='som53', priority=10, table_id=3):
        cfg, switch, tunnel = self.prepare_for_action(pattern, vnf_key)
        if action_type == 1:
            pushed_flows = mirror_to_tunnel(cfg, pattern, switch['id'], table_id, priority, tunnel)
            switch['flows'].extend(pushed_flows)
        elif action_type == 0:
            removed_flows = unmirror_from_tunnel(cfg, pattern, switch['id'], table_id)
            for flow in removed_flows:
                while flow in switch['flows']:
                    switch['flows'].remove(flow)
        self.update_action_logs(pattern, key=vnf_key, value=action_type)

    def mirror_to_som80_action(self, pattern, action_type, vnf_key='som80', priority=10, table_id=4):
        cfg, switch, tunnel = self.prepare_for_action(pattern, vnf_key)
        if action_type == 1:
            pushed_flows = mirror_to_tunnel(cfg, pattern, switch['id'], table_id, priority, tunnel)
            switch['flows'].extend(pushed_flows)
        elif action_type == 0:
            removed_flows = unmirror_from_tunnel(cfg, pattern, switch['id'], table_id)
            for flow in removed_flows:
                while flow in switch['flows']:
                    switch['flows'].remove(flow)
        self.update_action_logs(pattern, key=vnf_key, value=action_type)

    def map_to_octet(self, hp_container, src_dst):
        if len(hp_container['nat_map']['octet']) == 0:
            hp_container['nat_map']['src_dst'].append(src_dst)
            hp_container['nat_map']['octet'].append(2)
            idx = 0
        else:
            if src_dst in hp_container['nat_map']['src_dst']:
                idx = hp_container['nat_map']['src_dst'].index(src_dst)
            else:
                hp_container['nat_map']['src_dst'].append(src_dst)
                hp_container['nat_map']['octet'].append(max(hp_container['nat_map']['octet']) + 1)
                idx = -1
        return hp_container['nat_map']['octet'][idx]

    def spoof_pattern(self, hp_container, pattern, priority):
        ip_protocol, src, dst = src_dst_ips(pattern)
        src_dst = src + '.' + dst
        nat_ip = '.'.join(hp_container['ovs_ip'].split('.')[0:3]) + '.{0}'.format(self.map_to_octet(hp_container, src_dst))
        rnd_mac, rnd_mac_str = encode_ip_as_mac(nat_ip.split('.'))
        proto = ip_protocol_name(ip_protocol)
        container_obj = self.docker_cli.containers.get(hp_container['name'])
        cmd = 'arp -s {0} {1}'.format(nat_ip, rnd_mac)
        container_obj.exec_run(cmd)
        cmd = 'ovs-ofctl add-flow br-hp "table=0,priority={0},ip,{1},nw_src={2},nw_dst={3},action=set_field:{4}->eth_dst,set_field:{5}->nw_dst,set_field:{6}->nw_src,output:LOCAL"'.format(
            priority, proto, src, dst, hp_container['ovs_mac'], hp_container['ip'], nat_ip
        )
        container_obj.exec_run(cmd)
        cmd = 'ovs-ofctl add-flow br-hp "table=0,priority={0},ip,{1},nw_dst={2},action=set_field:{3}->eth_dst,set_field:{4}->nw_dst,set_field:{5}->nw_src,output:1"'.format(
            priority, proto, nat_ip, encode_ip_as_mac(src.split('.'))[0], src, dst
        )
        container_obj.exec_run(cmd)

    def redirect_to_honeypot_action(self, pattern, action_type, vnf_key='honeypot', priority=20, table_id=5):
        cfg, switch, tunnel = self.prepare_for_action(pattern, vnf_key)
        n_potted = [len(container['potted']) for container in self.containers['vnf']['honeypot']]
        hp_idx = np.argmin(n_potted)
        proto, src, dst = src_dst_ips(pattern)
        hp_container = self.containers['vnf']['honeypot'][hp_idx]
        hp_container['potted'].append(dst)
        if action_type == 1:
            pushed_flows = forward_to_tunnel(cfg, pattern, switch['id'], table_id, priority, tunnel)
            switch['flows'].extend(pushed_flows)
            src_dst = '{0}.{1}'.format(src, dst)
            if src_dst not in hp_container['nat_map']['src_dst']:
                self.spoof_pattern(hp_container, pattern, priority)
        elif action_type == 0:
            removed_flows = unforward_from_tunnel(cfg, pattern, switch['id'], table_id)
            for flow in removed_flows:
                while flow in switch['flows']:
                    switch['flows'].remove(flow)
        self.update_action_logs(pattern, key=vnf_key, value=action_type)

    def drop_connections_action(self, pattern, action_type, priority=30, table_id=6):
        cfg, switch, tunnel = self.prepare_for_action(pattern)
        timeout = 0  # change if more specific timeout is needed
        proto, src, dst = src_dst_ips(pattern)
        reverse_pattern = src_dst_pattern(proto, dst, src)
        if action_type == 1:
            pushed_flows = block(cfg, pattern, switch['id'], table_id, priority, timeout)
            pushed_flows.extend(block(cfg, reverse_pattern, switch['id'], table_id, priority, timeout))
            switch['flows'].extend(pushed_flows)
        elif action_type == 0:
            removed_flows = unblock(cfg, pattern, switch['id'], table_id)
            removed_flows.extend(unblock(cfg, reverse_pattern, switch['id'], table_id))
            for flow in removed_flows:
                while flow in switch['flows']:
                    switch['flows'].remove(flow)
        self.update_action_logs(pattern, key='drop_connections', value=action_type)

    def block_destination_action(self, pattern, action_type, priority=30, table_id=7):
        cfg, switch, tunnel = self.prepare_for_action(pattern)
        proto, src, dst = src_dst_ips(pattern)
        stars = '*.*.*.*'
        dst_pattern = src_dst_pattern(proto, stars, dst)
        reverse_dst_pattern = src_dst_pattern(proto, dst, stars)
        if action_type == 1:
            pushed_flows = block(cfg, dst_pattern, switch['id'], table_id, priority)
            pushed_flows.extend(block(cfg, reverse_dst_pattern, switch['id'], table_id, priority))
            switch['flows'].extend(pushed_flows)
        elif action_type == 0:
            removed_flows = unblock(cfg, dst_pattern, switch['id'], table_id)
            removed_flows.extend(unblock(cfg, reverse_dst_pattern, switch['id'], table_id))
            for flow in removed_flows:
                while flow in switch['flows']:
                    switch['flows'].remove(flow)
        self.update_action_logs(pattern, key='block_outgoing', value=action_type)

    def block_source_action(self, pattern, action_type, priority=30, table_id=8):
        cfg, switch, tunnel = self.prepare_for_action(pattern)
        proto, src, dst = src_dst_ips(pattern)
        stars = '*.*.*.*'
        src_pattern = src_dst_pattern(proto, src, stars)
        reverse_src_pattern = src_dst_pattern(proto, stars, src)
        if action_type == 1:
            pushed_flows = block(cfg, src_pattern, switch['id'], table_id, priority)
            pushed_flows.extend(block(cfg, reverse_src_pattern, switch['id'], table_id, priority))
            switch['flows'].extend(pushed_flows)
        elif action_type == 0:
            removed_flows = unblock(cfg, src_pattern, switch['id'], table_id)
            removed_flows.extend(unblock(cfg, reverse_src_pattern, switch['id'], table_id))
            for flow in removed_flows:
                while flow in switch['flows']:
                    switch['flows'].remove(flow)
        self.update_action_logs(pattern, key='block_incoming', value=action_type)

    def pass_action(self, pattern):
        pattern_idx = self.patterns.index(pattern)
        inds_to_switch_off = np.where(self.action_logs[pattern_idx, :] == 1)[0]
        action_type = 0
        for idx in inds_to_switch_off:
            action_idx = self.n_not_logged_actions + idx
            if action_idx in self.redirect_actions or action_idx in self.drop_actions or action_idx in self.block_actions:
                action = self.actions[action_idx]
                action(pattern, action_type)
                self.action_logs[pattern_idx, idx] = 0

    def test_policy(self, policy):
        if policy == 'mirror_all':
            patterns_to_mirror = []
            action_ids = []
            for i in range(len(self.patterns)):
                for j in range(len(self.action_categories)):
                    action_idx = self.n_not_logged_actions + j
                    if action_idx in self.mirror_actions and self.action_logs[i, j] == 0:
                        patterns_to_mirror.append(self.patterns[i])
                        action_ids.append(action_idx)
            self.step(patterns_to_mirror, action_ids)
        elif policy == 'spoof_all':
            patterns_to_forward = []
            action_ids = []
            for i in range(len(self.patterns)):
                for j in range(len(self.action_categories)):
                    action_idx = self.n_not_logged_actions + j
                    if action_idx in self.redirect_actions and self.action_logs[i, j] == 0:
                        patterns_to_forward.append(self.patterns[i])
                        action_ids.append(action_idx)
            self.step(patterns_to_forward, action_ids)
        elif policy == 'block_all':
            patterns_to_block = []
            action_ids = []
            for i in range(len(self.patterns)):
                for j in range(len(self.action_categories)):
                    action_idx = self.n_not_logged_actions + j
                    if (action_idx in self.drop_actions or action_idx in self.block_actions) and self.action_logs[i, j] == 0:
                        patterns_to_block.append(self.patterns[i])
                        action_ids.append(action_idx)
            self.step(patterns_to_block, action_ids)
        elif policy.startswith('block_subnet_'):
            subnet = policy.split('_')[-1]
            patterns_to_block = []
            action_ids = []
            for i in range(len(self.patterns)):
                remote_ip = '.'.join(self.patterns[i].split('.')[5:9])
                if remote_ip.startswith(subnet):
                    for j in range(len(self.action_categories)):
                        action_idx = self.n_not_logged_actions + j
                        if (action_idx in self.drop_actions or action_idx in self.block_actions) and self.action_logs[i, j] == 0:
                            patterns_to_block.append(self.patterns[i])
                            action_ids.append(action_idx)
            self.step(patterns_to_block, action_ids)
        elif policy == 'random':
            patterns = []
            action_ids = []
            for i in range(len(self.patterns)):
                j = random.randint(0, len(self.actions) - 1)
                if j > 0:
                    patterns.append(self.patterns[i])
                    action_ids.append(j)
            self.step(patterns, action_ids)
        else:
            print('Unknown policy! Will do nothing.')

    def update_action_logs(self, pattern, key, value):
        idx = self.patterns.index(pattern)
        i = self.action_categories.index(key)
        self.action_logs[idx, i] = value

    def botnet_attack(self):
        self.attack_containers = []
        cc_container = self.containers['attacker']['botnet_cc'][0]
        cc_ip = cc_container['ip']
        url = 'http://{0}/command'.format(cc_ip)
        jdata = {'command': 'status'}
        requests.post(url, json=jdata)
        local_path = '/home/env/Defender/iot/malware/beerai/queen.py'
        remote_path = '/tmp/queen.py'
        queen_container = random.choice(self.containers['app']['admin'])
        if self.debug:
            queen_container = self.containers['app']['admin'][0]
        queen_container_obj = self.docker_cli.containers.get(queen_container['name'])
        bee_containers = self.containers['app']['device']
        bee_ips = [container['ip'] for container in bee_containers]
        dns_ips = []
        for container in self.containers['app']['device']:
            for dns_ip in container['dns']:
                if dns_ip not in dns_ips:
                    dns_ips.append(dns_ip)
        self.attack_flows['a'] = ['.'.join(['6', ip, queen_container['ip']]) for ip in bee_ips]
        self.attack_flows['b'] = ['.'.join(['17', ip, dns_ip]) for ip in bee_ips for dns_ip in dns_ips]
        self.log['debug']['attack_flows'] = [(queen_container['ip'], ip) for ip in bee_ips]
        random.shuffle(bee_ips)
        cmd = 'python3 {0} {1}'.format(remote_path, ','.join(bee_ips))
        queen_cmd = ' '.join(cmd.split(' ')[0:2])
        bee_cmd = 'python3 /tmp/bee.py'
        self.attack_containers.append((queen_container, queen_cmd))
        for bee_container in bee_containers:
            self.attack_containers.append((bee_container, bee_cmd))
        self.copy_to_container(local_path, queen_container_obj, remote_path)
        queen_container_obj.exec_run(cmd)

    def _attack(self, target_prefix=''):
        self.attack_containers = []
        cc_container = self.containers['attacker']['botnet_cc'][0]
        cc_ip = cc_container['ip']
        url = 'http://{0}/command'.format(cc_ip)
        potential_target_names = [
            ip for name, ip in zip(self.resolv['names'], self.resolv['ips']) if name.startswith(target_prefix)
        ]
        if self.log_packets:
            n_targets = 1
        else:
            n_targets = random.randint(1, len(potential_target_names))
        shuffle(potential_target_names)
        targets = potential_target_names[:n_targets]
        local_path = '/home/env/Defender/iot/malware/beerai/bee.py'
        remote_path = '/tmp/bee.py'
        potential_bee_containers = self.containers['app']['device']
        shuffle(potential_bee_containers)
        n = len(potential_bee_containers) // 2 + 1
        bee_containers = potential_bee_containers[0:n]
        bees = [container['ip'] for container in bee_containers]
        bee_cmd = 'python3 {0}'.format(remote_path)
        for bee_container in bee_containers:
            self.attack_containers.append((bee_container, bee_cmd))
            bee_container_obj = self.docker_cli.containers.get(bee_container['name'])
            self.copy_to_container(local_path, bee_container_obj, remote_path)
            code, output = bee_container_obj.exec_run(bee_cmd, detach=True, tty=True)
            print(bee_container['name'], bee_container['ip'])
        return url, bees, targets

    def exfiltration_attack(self):
        url, bees, targets = self._attack()
        self.log['debug']['attack_flows'] = []
        dns_ips = []
        for container in self.containers['app']['device']:
            for dns_ip in container['dns']:
                if dns_ip not in dns_ips:
                    dns_ips.append(dns_ip)
        for bee_ip in bees:
            for target_ip in dns_ips:
                self.log['debug']['attack_flows'].append((bee_ip, target_ip))
        print(self.log['debug']['attack_flows'])
        self.attack_flows['a'] = []
        self.attack_flows['b'] = ['.'.join(['17', bee_ip, dns_ip]) for bee_ip in bees for dns_ip in dns_ips]
        jdata = {'command': 'exfiltrate'}
        r = requests.post(url, json=jdata)

    def scan_attack(self):
        url, bees, targets = self._attack()
        self.log['debug']['attack_flows'] = []
        for bee_ip in bees:
            for target_ip in targets:
                self.log['debug']['attack_flows'].append((bee_ip, target_ip))
        dns_ips = []
        for container in self.containers['app']['device']:
            for dns_ip in container['dns']:
                if dns_ip not in dns_ips:
                    dns_ips.append(dns_ip)
        self.attack_flows['a'] = ['.'.join(['6', bee_ip, target_ip]) for bee_ip in bees for target_ip in targets]
        self.attack_flows['b'] = ['.'.join(['17', bee_ip, dns_ip]) for bee_ip in bees for dns_ip in dns_ips]
        jdata = {'command': 'scan_', 'target': targets}
        r = requests.post(url, json=jdata)

    def exploit_attack(self):
        url, bees, targets = self._attack()
        self.log['debug']['attack_flows'] = []
        for bee_ip in bees:
            for target_ip in targets:
                self.log['debug']['attack_flows'].append((bee_ip, target_ip))
        dns_ips = []
        for container in self.containers['app']['device']:
            for dns_ip in container['dns']:
                if dns_ip not in dns_ips:
                    dns_ips.append(dns_ip)
        self.attack_flows['a'] = ['.'.join(['6', bee_ip, target_ip]) for bee_ip in bees for target_ip in targets]
        self.attack_flows['b'] = ['.'.join(['17', bee_ip, dns_ip]) for bee_ip in bees for dns_ip in dns_ips]
        jdata = {'command': 'exploit_', 'target': targets}
        r = requests.post(url, json=jdata)

    def slowloris_attack(self):
        url, bees, targets = self._attack(target_prefix = 'unknown')
        self.log['debug']['attack_flows'] = []
        for bee_ip in bees:
            for target_ip in targets:
                self.log['debug']['attack_flows'].append((bee_ip, target_ip))
        dns_ips = []
        for container in self.containers['app']['device']:
            for dns_ip in container['dns']:
                if dns_ip not in dns_ips:
                    dns_ips.append(dns_ip)
        self.attack_flows['a'] = ['.'.join(['6', bee_ip, target_ip]) for bee_ip in bees for target_ip in targets]
        self.attack_flows['b'] = ['.'.join(['17', bee_ip, dns_ip]) for bee_ip in bees for dns_ip in dns_ips]
        jdata = {'command': 'slowloris_', 'target': targets}
        r = requests.post(url, json=jdata)

    def start_episode(self, attack_name=None, start_time=0):

        t_start = time()
        self.status = 'STARTING'

        # shuffle server ips

        ips = []
        for category in ['app', 'attacker']:
            for key in self.containers[category].keys():
                for container in self.containers[category][key]:
                    if container['network'] == 'server':
                        ips.append(container['ip'])
        shuffle(ips)
        ip_generator = iter(ips)
        for category, key, idx in self.resolv['categories']:
            ip = next(ip_generator)
            self.containers[category][key][idx]['ip'] = ip
            if category == 'attacker' and 'cc' in key:
                cc_ip = ip
        self.resolv['ips'] = ips
        self.update_dns_tables(cc_ip)
        if self.debug:
            print(self.resolv)

        # reconnect server containers

        containers = []
        for category in ['app', 'attacker']:
            for key in self.containers[category].keys():
                for container in self.containers[category][key]:
                    if container['network'] == 'server':
                        containers.append(container)
        self.clean_networks(['server'])
        self.connect_containers_to_networks(containers)

        # start attack thread

        self.attack_containers = []
        try:
            attack = getattr(self, attack_name)
            attack_thread = Timer(start_time, attack)
            attack_thread.setDaemon(True)
            attack_thread.start()
            self.score_a, self.score_b = self.score_coeff[attack_name]
        except Exception as e:
            print(e)
            print('Unknown attack vector!')
            self.score_a = 0
            self.score_b = 0
        self.log['attack'] = attack_name

        # sleep to deque state frames from the previous episode

        t = time()
        if t < t_start + self.time_window:
            sleep(t_start + self.time_window - t)

        self.log['debug']['episode'] += 1
        self.log['debug']['episode_start_time'] = time()
        self.status = 'EPISODE'
        print('\n{0}: {1}\n'.format(self.status, self.log['debug']['episode']))

    def reset(self):

        t_start = time()
        self.status = 'RESETTING'
        if self.debug:
            print('\n{0}\n'.format(self.status))

        # log episode  stats

        a = ''
        if self.log['attack'] is not None:
            a = self.log['attack']
        af = []
        for flows in self.log['debug']['attack_flows']:
            af.append(flows[0] + '->' + flows[1])
        line = ','.join([
            str(self.log['debug']['episode']),
            str(self.log['debug']['episode_start_time']),
            str(t_start),
            a,
            ','.join(af)
        ])
        with open(self.gym_log_file, 'a') as f:
            f.write(line + '\n')
        self.attack_flows = {'a': [], 'b': []}

        # reset sdn flows tables

        for net in self.ovs_nets:
            for switch in net['switches']:
                if switch['name'] in self.sdn['switches']:
                    for flow in switch['flows']:
                        switch['cfg'].delete_flow(flow['node_id'], flow['table_id'], flow['flow_id'])
                    switch['flows'] = []
        self.action_types = [1 for action in self.actions]

        # send stop command to cc

        cc_container = self.containers['attacker']['botnet_cc'][0]
        cc_ip = cc_container['ip']
        url = 'http://{0}/command'.format(cc_ip)
        jdata = {'command': 'stop'}
        requests.post(url, json=jdata)

        # stop all malicious commands

        malicious_commands = []
        for container, cmd in self.attack_containers:
            self.kill_process(container, cmd)
            if cmd not in malicious_commands:
                malicious_commands.append(cmd)
        for container in self.containers['vnf']['honeypot']:
            for cmd in malicious_commands:
                self.kill_process(container, cmd)

        # clean /tmp directory on infected containers and honeypots

        for container, command in self.attack_containers:
            d = '{0}/tmp'.format(container['volume'])
            clean_directory(d)
        for container in self.containers['vnf']['honeypot']:
            d = '{0}/tmp'.format(container['volume'])
            clean_directory(d)

        while self.infected != []:
            self.infected = []

        # clean vnf logs

        for key in self.containers['vnf'].keys():
            if key.startswith('snort'):
                for container in self.containers['vnf'][key]:
                    fpath = '{0}/log/snort/alert'.format(container['volume'])
                    with open(fpath, 'w') as f:
                        f.close()
        for container in self.containers['vnf']['honeypot'] + self.containers['vnf']['som53'] + self.containers['vnf']['som80']:
            fpath = '{0}/log/alerts'.format(container['volume'])
            with open(fpath, 'w') as f:
                f.close()


        # nulify the state
        
        while True:
            if self.lock:
                print('Locked!')
            else:
                self.lock = True
                #self.patterns = []
                n_patterns = len(self.patterns)
                self.current_flows = []
                self.vnf_logs = np.zeros((n_patterns, self.n_vnf_features))
                self.sum_vnf_logs = np.zeros((n_patterns, self.n_vnf_features))
                self.action_logs = np.zeros((n_patterns, self.n_action_categories))
                self.lock = False
                break

        t = time()
        if t < t_start + self.time_window:
            sleep(t_start + self.time_window - t)
        self.status = 'READY'

    def define_network_graph(self, t_window = None):
        if t_window is None:
            t_window = int(self.time_window)
        n_features = 4

        # define network graph used to calculate score

        nodes = []
        node_types = []
        n_rows = 3
        n_nodes_per_row = [0 for _ in range(n_rows)]
        for container in self.containers['app']['admin'] + self.containers['app']['device']:
            nodes.append(container['ip'])
            node_type = container['name'].split('_')[0]
            node_types.append(node_type)
            if node_type == 'admin':
                row_i = 0
            elif node_type == 'device':
                row_i = 1
            n_nodes_per_row[row_i] += 1
        serv_row_i = 2
        for name in self.resolv['names']:
            nodes.append(name)
            node_type_with_digit = name.split('.')[0]
            node_type = ''.join([symbol for symbol in node_type_with_digit if symbol.isdigit()==False])
            node_types.append(node_type)
            n_nodes_per_row[serv_row_i] += 1
        for dns_ip in self.containers['app']['device'][0]['dns']:
            nodes.append(dns_ip)
            node_types.append('dns')
            n_nodes_per_row[serv_row_i] += 1
        node_positions = []
        for i in range(len(n_nodes_per_row)):
            row_y = float(i)/(len(n_nodes_per_row) - 1)
            for j in range(n_nodes_per_row[i]):
                node_x = float(j)/(n_nodes_per_row[i] - 1)
                node_positions.append([node_x, row_y])
        n_nodes = len(nodes)
        src_node_values = deque(maxlen=t_window)
        dst_node_values = deque(maxlen=t_window)
        for _ in range(t_window):
            src_node_values.append(np.zeros((n_nodes, n_features)))
            dst_node_values.append(np.zeros((n_nodes, n_features)))
        edges = []
        for src_container in self.containers['app']['admin']:
            for dst_container in self.containers['app']['device']:
                edges.append((src_container['ip'], dst_container['ip']))
        for src_container in self.containers['app']['device']:
            for name in self.resolv['names']:
                edges.append((src_container['ip'], name))
            for dns_ip in self.containers['app']['device'][0]['dns']:
                edges.append((src_container['ip'], dns_ip))
        n_edges = len(edges)
        edge_values = deque(maxlen=t_window)
        reward_flows = deque(maxlen=t_window)
        flow_values = deque(maxlen=t_window)
        n_flows = len(self.current_flows)
        n_w = 4
        for _ in range(t_window):
            edge_values.append(np.zeros((n_edges, n_features)))
            reward_flows.append(np.zeros(n_flows))
            flow_values.append(np.zeros((n_flows, n_w)))
        self.network_graph = {
            'nodes': nodes,
            'src_node_values': src_node_values,
            'dst_node_values': dst_node_values,
            'flow_values': flow_values,
            'reward_flows': reward_flows,
            'edges': edges,
            'edge_values': edge_values,
            'frame_status': deque([0 for _ in range(t_window)], maxlen=t_window)
        }

        # extend the graph for vizualization purposes

        vnfs = []
        vnf_src_dst = []
        ips = self.resolv['ips']
        n_actions = len(self.action_logs)
        for i in range(len(self.action_categories)):
            for j in range(n_actions):
                if self.action_logs[j, i] > 0:
                    proto, src, dst_ip = src_dst_ips(self.patterns[j])
                    if dst_ip in ips:
                        dst = self.resolv['names'][ips.index(dst_ip)]
                    else:
                        dst = dst_ip
                    src_position = node_positions[nodes.index(src), :]
                    dst_position = node_positions[nodes.index(dst), :]
                    src_dst = [src_position.tolist(), dst_position.tolist()]
                    if src_dst not in vnf_src_dst:
                        vnf_src_dst.append(src_dst)
                        vnfs.append([self.action_categories[i]])
                    else:
                        idx = vnf_src_dst.index(src_dst)
                        vnfs[idx].append(self.action_categories[i])
        src_node_deltas = (src_node_values[-1] - src_node_values[0])
        dst_node_deltas = (dst_node_values[-1] - dst_node_values[0])
        edge_deltas = edge_values[-1] - edge_values[0]
        self.log['graph'] = {
            'nodes': nodes,
            'node_types': node_types,
            'node_positions': node_positions,
            'src_node_deltas': src_node_deltas.tolist(),
            'dst_node_deltas': dst_node_deltas.tolist(),
            'edges': edges,
            'edge_deltas': edge_deltas.tolist(),
            'vnfs': vnfs,
            'vnf_src_dst_positions': vnf_src_dst,
        }

    def find_delta_windows(self):
        t_start = self.network_graph['frame_status'].index(0)
        t_end = int(self.time_window) - 1 - list(self.network_graph['frame_status'])[::-1].index(0)
        return t_start, t_end

    def monitor_network_graph(self):
        sensor_activity_fpath = 'log/sensor_activity'
        malware_activity_fpath = 'tmp/malware_activity'
        th = Thread(target=self.update_network_graph, args=(sensor_activity_fpath, malware_activity_fpath, self.update_interval))
        th.setDaemon(True)
        th.start()
        th = Thread(target=self.check_for_malware)
        th.setDaemon(True)
        th.start()

    def check_for_malware(self, malware_activity_fpath = 'tmp/malware_activity'):
        while True:
            t_start = time()
            if self.status != 'RESETTING':
                for container in self.containers['app']['device']:
                    log_file = '{0}/{1}'.format(container['volume'], malware_activity_fpath)
                    try:
                        open(log_file, 'r').close()
                        if container['ip'] not in self.infected:
                            self.infected.append(container['ip'])
                    except:
                        pass
            t = time()
            if t < t_start + self.update_interval:
                sleep(self.update_interval + t_start - t)

    def update_network_graph(self, sensor_activity_fpath, malware_activity_fpath, interval=1, key='sensors'):
        while True:
            t_start = time()

            # update network graph used to calculate score

            app_edge_values, app_flows, app_flow_values = self.update_edges(
                self.containers['app']['admin'] + self.containers['app']['device'], sensor_activity_fpath, key=key
            )
            attacker_edge_values, attacker_flows, attacker_flow_values = self.update_edges(
                [container for container,cmd in self.attack_containers], malware_activity_fpath, key=key
            )
            edge_values = np.hstack([app_edge_values, attacker_edge_values])
            src_node_values = np.zeros_like(self.network_graph['src_node_values'][0])
            dst_node_values = np.zeros_like(self.network_graph['dst_node_values'][0])
            for i,edge in enumerate(self.network_graph['edges']):
                src, dst = edge
                src_node_values[self.network_graph['nodes'].index(src), :] += edge_values[i, :]
                dst_node_values[self.network_graph['nodes'].index(dst), :] += edge_values[i, :]
            self.network_graph['src_node_values'].append(src_node_values)
            self.network_graph['dst_node_values'].append(dst_node_values)
            self.network_graph['edge_values'].append(edge_values)
            n_windows = len(self.network_graph['edge_values'])
            current_flows = self.current_flows
            n_flows = len(current_flows)
            n_counts = 4
            flows = [app_flows, attacker_flows]
            flow_values = [app_flow_values, attacker_flow_values]
            reward_frame = np.zeros((n_flows, n_counts))
            for j in range(2):
                for flow, flow_feature_vector in zip(flows[j], flow_values[j]):
                    idx = flow_follows_pattern(flow, current_flows)
                    reward_frame[idx, j*2:j*2+2] = flow_feature_vector
            self.network_graph['flow_values'].append(reward_frame)
            self.network_graph['reward_flows'].append(current_flows)

            # update frame status

            index_to_look = [0,1] # we restart attack so those indexes should not be a problem
            if np.any(self.network_graph['src_node_values'][-2][:, index_to_look] > self.network_graph['src_node_values'][-1][:, index_to_look]):
                self.network_graph['frame_status'].append(1)
            else:
                self.network_graph['frame_status'].append(0)

            # calculate score based on the network graph

            self.update_graph_reward()

            # update log graph used for vizualization

            nodes = self.log['graph']['nodes']
            node_positions = np.array(self.log['graph']['node_positions'])
            vnfs = []
            vnf_src_dst = []
            ips = self.resolv['ips']
            n_actions = len(self.action_logs)
            for i in range(len(self.action_categories)):
                for j in range(n_actions):
                    if self.action_logs[j, i] > 0:
                        proto, src, dst_ip = src_dst_ips(self.patterns[j])
                        if dst_ip in ips:
                            dst = self.resolv['names'][ips.index(dst_ip)]
                        else:
                            dst = dst_ip
                        src_position = node_positions[nodes.index(src), :]
                        dst_position = node_positions[nodes.index(dst), :]
                        src_dst = [src_position.tolist(), dst_position.tolist()]
                        if src_dst not in vnf_src_dst:
                            vnf_src_dst.append(src_dst)
                            vnfs.append([self.action_categories[i]])
                        else:
                            idx = vnf_src_dst.index(src_dst)
                            vnfs[idx].append(self.action_categories[i])
            delta_start, delta_end = self.find_delta_windows()
            src_node_deltas = (self.network_graph['src_node_values'][delta_end] - self.network_graph['src_node_values'][delta_start])
            dst_node_deltas = (self.network_graph['dst_node_values'][delta_end] - self.network_graph['dst_node_values'][delta_start])
            edge_deltas = self.network_graph['edge_values'][delta_end] - self.network_graph['edge_values'][delta_start]
            self.log['graph']['src_node_deltas'] = src_node_deltas.tolist()
            self.log['graph']['dst_node_deltas'] = dst_node_deltas.tolist()
            self.log['graph']['edge_deltas'] = edge_deltas.tolist()
            self.log['graph']['vnfs'] = vnfs
            self.log['graph']['vnf_src_dst_positions'] = vnf_src_dst

            t = time()
            if t < t_start + interval:
                sleep(interval + t_start - t)
            else:
                print('DELAY :/')

    def get_score_coeff(self, attack_name):
        return self.score_coeff[attack_name]

    def set_score_coeff(self, attack_name, a, b):
        self.score_coeff[attack_name] = (a, b)

    def update_graph_reward(self):
        w_len = self.time_window
        n_len = 4
        n_nodes = len(self.network_graph['nodes'])
        n_src = np.zeros((n_nodes, n_len))
        n_dst = np.zeros((n_nodes, n_len))
        n_delta_src = np.zeros((n_nodes, n_len))
        n_delta_dst = np.zeros((n_nodes, n_len))
        delta_start, delta_end = self.find_delta_windows()
        node_delta_vals_src = self.network_graph['src_node_values'][delta_end] - self.network_graph['src_node_values'][delta_start]
        node_delta_vals_dst = self.network_graph['dst_node_values'][delta_end] - self.network_graph['dst_node_values'][delta_start]

        # synchronize flows in each reward frame

        reward_frames = []
        current_flows = self.current_flows
        n_flows = len(current_flows)
        for t in range(len(self.network_graph['reward_flows'])):
            reward_frame = np.zeros((n_flows, n_len))
            for flow, value in zip(self.network_graph['reward_flows'][t], self.network_graph['flow_values'][t]):
                if flow in current_flows:
                    idx = flow_follows_pattern(flow, current_flows)
                    reward_frame[idx, :] = value
            reward_frames.append(reward_frame)
        self.reward_flows = list(current_flows)

        # calculate deltas

        node_delta_vals = reward_frames[delta_end] - reward_frames[delta_start]
        for i in range(n_nodes):
            node_value_end_src = self.network_graph['src_node_values'][delta_end][i]
            node_value_end_dst = self.network_graph['dst_node_values'][delta_end][i]
            node_delta_value_src = node_delta_vals_src[i]
            node_delta_value_dst = node_delta_vals_dst[i]
            node_value_src = node_value_end_src + (w_len - 1 - delta_end) * node_delta_value_src / (delta_end - delta_start + 1)
            node_value_dst = node_value_end_dst + (w_len - 1 - delta_end) * node_delta_value_dst / (delta_end - delta_start + 1)
            n_src[i, :] = node_value_src
            n_dst[i, :] = node_value_dst
            n_delta_src[i, :] = node_delta_value_src
            n_delta_dst[i, :] = node_delta_value_dst
        n = np.zeros((n_flows, n_len))
        n_delta = np.zeros((n_flows, n_len))
        for i in range(n_flows):
            node_value_end = reward_frames[delta_end][i,:]
            node_delta_value = node_delta_vals[i,:]
            node_value = node_value_end + (w_len - 1 - delta_end) * node_delta_value / (delta_end - delta_start + 1)
            n[i, :] = node_value
            n_delta[i, :] = node_delta_value
            #print(node_value, node_delta_value)
        self.n_connected_failed = n.tolist()
        n_delta_per_sec_src = n_delta_src / (delta_end - delta_start + 1)
        n_delta_per_sec_dst = n_delta_dst / (delta_end - delta_start + 1)
        n_delta_per_sec = n_delta / (delta_end - delta_start + 1)
        if self.debug and np.any(n_delta_per_sec_src < 0) and self.status == 'EPISODE':
            for node,value0,value1 in zip(self.network_graph['nodes'],self.network_graph['src_node_values'][0],self.network_graph['src_node_values'][-1]):
                print(node,value0,value1)
            for edge,value0,value1 in zip(self.network_graph['edges'],self.network_graph['edge_values'][0],self.network_graph['edge_values'][-1]):
                print(edge,value0,value1)
        self.n_connected_failed_delta = n_delta_per_sec
        #self.n_connected_failed_delta_src = n_delta_per_sec_src.tolist()
        #self.n_connected_failed_delta_dst = n_delta_per_sec_dst.tolist()
        #score_array_src = n_delta_per_sec_src[:,0] - self.score_a * n_delta_per_sec_src[:,1] - self.score_b * n_delta_per_sec_src[:,2] + n_delta_per_sec_src[:,3]
        #score_array_dst = n_delta_per_sec_dst[:,0] - self.score_c * n_delta_per_sec_dst[:,1] - self.score_d * n_delta_per_sec_dst[:,2] + n_delta_per_sec_dst[:,3]
        #self.score, self.score_can_be_trusted = self.calc_score(n_delta_per_sec_src, n_delta_per_sec_dst)
        #self.log['score'] = self.score
        sum_state = np.sum(self.state_f[-1],axis=0)
        np.set_printoptions(precision=2)
        #print('Score: {0}, queue size = {1}'.format(self.score, self.log['debug']['flow_queue_size']))
        if self.debug:
            print('Sum state = {0}'.format(sum_state))
            print('Connected & failed per source:\n{0}'.format(n_delta_per_sec_src))
            print('Connected & failed per destination:\n{0}'.format(n_delta_per_sec_dst))
            print('Connected & failed per flow:\n{0}'.format(n_delta_per_sec))

    def calculate_score(self, flows=None, delay=4):
        if flows is None:
            flows = self.reward_flows
        n_flows = len(flows)
        avg_scores = np.zeros(n_flows)
        reward_flows = self.current_flows
        counts = np.vstack(self.count_frames[-delay:])
        scores = np.vstack(self.reward_frames[-delay:])
        avg_counts = np.mean(counts, 0)
        for i in range(n_flows):
            flow = flows[i]
            if flow in reward_flows:
                idx = flow_follows_pattern(flow, reward_flows)
                avg_scores[i] = np.mean(scores[:, idx], 0)
        return avg_scores.tolist(), avg_counts.tolist()

    def update_edges(self, containers, activity_fpath, key):
        flows = list(self.current_flows)
        n_flows = len(flows)
        flow_values = np.zeros((n_flows, 2))
        n_edges = len(self.network_graph['edges'])
        edge_values = np.zeros((n_edges, 2))
        for container in containers:
            src_ip = container['ip']
            dns_ips = container['dns']
            log_file = '{0}/{1}'.format(container['volume'], activity_fpath)
            try:
                with open(log_file, 'r') as f:
                    jdata = json.load(f)
                activity = jdata[key]
                for item in activity:
                    dst = item['ip']
                    if dst in self.resolv['ips']:
                        dst_idx = self.resolv['ips'].index(dst)
                        dst_name = self.resolv['names'][dst_idx]
                        dst_ip = self.resolv['ips'][dst_idx]
                    elif dst in self.resolv['names']:
                        dst_idx = self.resolv['names'].index(dst)
                        dst_name = self.resolv['names'][dst_idx]
                        dst_ip = self.resolv['ips'][dst_idx]
                    else:
                        dst_name = dst
                        dst_ip = dst
                    n_connected = item['n_connected']
                    n_failed = item['n_failed']
                    edge = (src_ip, dst_name)
                    if edge in self.network_graph['edges']:
                        idx = self.network_graph['edges'].index(edge)
                        edge_values[idx, 0] = n_connected
                        edge_values[idx, 1] = n_failed
                    if src_ip in self.device_ips:
                        flows_to_find = [src_dst_pattern(6, src_ip, dst_ip)]
                        #if dst_name != dst_ip:
                        #     flows_to_find += [src_dst_pattern(17, src_ip, dns_ip) for dns_ip in dns_ips]
                    elif dst_ip in self.device_ips:
                        flows_to_find = [src_dst_pattern(6, dst_ip, src_ip)]
                    for flow_to_find in flows_to_find:
                        if flow_to_find in flows:
                            idx = flows.index(flow_to_find)
                            flow_values[idx, 0] = n_connected
                            flow_values[idx, 1] = n_failed
            except Exception as e:
                if self.debug:
                    print(e)
                pass
        return edge_values, flows, flow_values

    def render(self):
        pass

    def close(self):
        pass