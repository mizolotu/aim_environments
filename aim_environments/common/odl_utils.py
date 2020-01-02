import requests

from lxml import etree
from dicttoxml import dicttoxml

from aim_environments.common.net_utils import src_dst_ips, ip_mask

class Nodes:

    ns = {
        'n': 'urn:opendaylight:inventory',
        'f': 'urn:opendaylight:flow:inventory',
        'e': 'urn:opendaylight:openflowplugin:extension:nicira:action',
    }

    xpath = {
        'mac_by_port_id': '//n:nodes/n:node/n:node-connector[./n:id/text()=$port_id]/f:hardware-address/text()',
        'tables_on_node': '//n:nodes/n:node[./n:id/text()=$node_id]/f:table[./f:flow]/f:id/text()'
    }

    def __init__(self, ip, port, user, password):
        self.odl_ip = ip
        self.odl_port = port
        self.auth = requests.auth.HTTPBasicAuth(user, password)
        self.headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'}
        self.op = 'http://' + ip + ':' + str(port) + '/restconf/operational/opendaylight-inventory:nodes'
        self.cfg = 'http://' + ip + ':' + str(port) + '/restconf/config/opendaylight-inventory:nodes'

    def push_flow(self, node, flow_body):
        # if flow_body is None:
        # return -1
        # extracting id and table_id from flow body
        xml_root = flow_body.getroot()
        table = xml_root.xpath("//f:flow/f:table_id/text()", namespaces=self.ns)
        flow = xml_root.xpath("//f:flow/f:id/text()", namespaces=self.ns)
        # pushing flow
        if len(table) > 0 and len(flow) > 0:
            # print('Pushing flow ' + flow[0] + ' to table ' + table[0] + ' of switch ' + node)
            url = self.cfg + '/node/' + node + '/table/' + table[0] + '/flow/' + flow[0]
            body = etree.tostring(flow_body)
            r = requests.put(url=url, data=body, headers=self.headers, auth=self.auth)
            if int(r.status_code) >= 200 and int(r.status_code) < 300:
                code = 0
            else:
                code = 1
                print(body)
                print((r.text))
        else:
            code = -1  # 0
        return code

    def delete_flow(self, node_id, table_id, flow_id):
        # print('Deleting flow {0} from table {1} of switch {2}'.format(flow_id,table_id,node_id))
        url = '{0}/node/{1}/table/{2}/flow/{3}'.format(self.cfg, node_id, table_id, flow_id)
        r = requests.delete(url=url, headers=self.headers, auth=self.auth)
        if int(r.status_code) >= 200 and int(r.status_code) < 300:
            code = 0
        else:
            code = 1
            #print((r.text))
        return code

    def find_tables(self, node_id):
        req = requests.get(self.op, auth=self.auth, headers=self.headers, stream=True)
        req.raw.decode_content = True
        tree = etree.parse(req.raw)
        nodes_root = tree.getroot()
        table_ids = nodes_root.xpath(self.xpath['tables_on_node'], node_id=node_id, namespaces=self.ns)
        return table_ids

    def delete_table(self, node_id, table_id):
        #print('Deleting table ' + table_id + ' of switch ' + node_id)
        url = self.cfg + '/node/' + node_id + '/table/' + table_id
        #print(url)
        r = requests.delete(url=url, headers=self.headers, auth=self.auth)
        if int(r.status_code) >= 200 and int(r.status_code) < 300:
            code = 0
        else:
            code = 1
            print((r.text))
            print((r.status_code))
        return code

class Flow():

    def __init__(self, switch, table, id, priority, ns, timeout=0):
        self.switch = switch
        self.table = table
        self.id = id
        self.priority = priority
        self.timeout = timeout
        self.ns = ns
        flow_body_dict = {
            'id': self.id,
            'table_id': self.table,
            'priority': self.priority,
            'hard-timeout': self.timeout,
            'match': {},
            'instructions': {}
        }
        flow_body_bytes = dicttoxml(flow_body_dict, root=False, attr_type=False)
        flow_str = '<flow xmlns="' + self.ns['f'] + '">' + flow_body_bytes.decode("utf-8") + '</flow>'
        self.body = etree.fromstring(flow_str).getroottree()

    def match(self, match_list):
        match_found = self.body.find('f:match', namespaces=self.ns)
        for item in match_list:
            last_element_found = match_found
            xp = 'f:match'
            for i in range(len(item)-1):
                xp += '/{0}:{1}'.format('f', item[i])
                element_found = self.body.xpath(xp, namespaces=self.ns)
                if element_found == []:
                    if i == len(item) - 2:
                        etree.SubElement(last_element_found, '{%s}%s' % (self.ns['f'], item[i])).text = str(item[i+1])
                    else:
                        last_element_found = etree.SubElement(last_element_found, '{%s}%s' % (self.ns['f'], item[i]))
                else:
                    last_element_found = element_found[0]

    def instructions(self, instruction_list, order_list):
        instructions_found = self.body.find('f:instructions', namespaces=self.ns)
        for i_item,o_item in zip(instruction_list,order_list):
            instruction_found = etree.SubElement(instructions_found, '{%s}%s' % (self.ns['f'], 'instruction'))
            etree.SubElement(instruction_found, '{%s}%s' % (self.ns['f'], 'order')).text = str(o_item)
            element_found = instruction_found
            if i_item[0] == 'apply-actions':
                self.apply_actions(element_found, [item['action'] for item in i_item[1]], [item['order'] for item in i_item[1]], [item['ns'] for item in i_item[1]])
            else:
                for i in range(len(i_item) - 1):
                    if i == len(i_item) - 2:
                        etree.SubElement(element_found, '{%s}%s' % (self.ns['f'], i_item[i])).text = str(i_item[i + 1])
                    else:
                        element_found = etree.SubElement(element_found, '{%s}%s' % (self.ns['f'], i_item[i]))

    def apply_actions(self, instruction, action_list, order_list, ns_list):
        #print(order_list)
        apply_actions = etree.SubElement(instruction, '{%s}%s' % (self.ns['f'], 'apply-actions'))
        for a_item,o_item,n_item in zip(action_list,order_list,ns_list):
            new_action = etree.SubElement(apply_actions, '{%s}%s' % (self.ns['f'], 'action'))
            etree.SubElement(new_action, '{%s}%s' % (self.ns['f'], 'order')).text = str(o_item)
            last_element_found = new_action
            #print(a_item)
            for i in range(len(a_item)):
                xp = 'f:instructions/f:instruction/f:apply-actions/f:action[./f:order/text()=$ord]'
                #print(xp)
                #print(a_item[i])
                for j in range(len(a_item[i])-1):
                    xp += '/{0}:{1}'.format(n_item,a_item[i][j])
                    element_found = self.body.xpath(xp, ord=o_item, namespaces=self.ns)
                    #print(xp,element_found)
                    if element_found == []:
                        if j == len(a_item[i]) - 2 and a_item[i][j+1] != None:
                            etree.SubElement(last_element_found, '{%s}%s' % (self.ns[n_item], a_item[i][j])).text = str(a_item[i][j+1])
                        else:
                            last_element_found = etree.SubElement(last_element_found, '{%s}%s' % (self.ns[n_item], a_item[i][j]))
                    else:
                        last_element_found = element_found[0]

    @staticmethod
    def in_port(port):
        inp = ['in-port', port]
        return inp

    @staticmethod
    def ethernet_type(etype):
        eth_type = ['ethernet-match','ethernet-type','type', etype]
        return eth_type

    @staticmethod
    def ethernet_src(mac):
        eth_src = ['ethernet-match', 'ethernet-source', 'address', mac]
        return eth_src

    @staticmethod
    def ethernet_dst(mac):
        eth_dst = ['ethernet-match', 'ethernet-destination', 'address', mac]
        return eth_dst

    @staticmethod
    def ip_protocol(proto):
        ip_proto = ['ip-match', 'ip-protocol', proto]
        return ip_proto

    @staticmethod
    def ip_dscp(dscp):
        ip_d = ['ip-match', 'ip-dscp', dscp]
        return ip_d

    @staticmethod
    def go_to_table(table):
        to_table = ['go-to-table', 'table_id', table]
        return to_table

    @staticmethod
    def output_to_port(connector):
        to_port = ['output-action', 'output-node-connector', connector]
        return to_port

def get_iot_ports(op, iot_switch):
    non_device_ports = [iot_switch['local']['port'], iot_switch['external']['port']] + [tunnel['port'] for tunnel in iot_switch['tunnels']]
    iot_switch_id = 'openflow:{0}'.format(str(int(''.join(iot_switch['local']['mac'].split(':')),16)))
    iot_switch_ports = op.get_ports(iot_switch_id)
    device_connectors = [connector for connector in iot_switch_ports if connector['port'] not in non_device_ports]
    devices = []
    for connector in device_connectors:
        if connector['mac'].startswith('fe'):
            devices.append({
                'mac': '52' + connector['mac'][2:],
                'port': ''.join(connector['port'])
            })
    return devices

def init_flow_tables(cfg, switch_id, patch_id, priority, n_tables=10):

    # clean old tables

    table_ids = cfg.find_tables(switch_id)
    for table_id in table_ids:
        code = cfg.delete_table(switch_id, table_id)
        if code != 0:
            print(code)
            print('Problems with deleting table {0}'.format(table_id))

    # init several tables with one default rule in each

    tables = []
    for i in range(n_tables):
        tables.append({'id': i, 'flows': []})
        if i == n_tables - 1:
            id = 'table{0}_to_table{1}'.format(i, i + 1)
            flow = Flow(switch_id, i, id, priority, cfg.ns)
            flow.instructions([
                Flow.go_to_table(i + 1),
                ['apply-actions', [
                    {'action': [Flow.output_to_port(patch_id)], 'order': 0, 'ns': 'f'}
                ]]
            ], [0, 1])
        elif i < n_tables - 1:
            id = 'table{0}_to_table{1}'.format(i,i+1)
            flow = Flow(switch_id, i, id, priority, cfg.ns)
            flow.instructions([
                Flow.go_to_table(i+1)
            ], [0])
        else:
            id = 'table{0}_normal'.format(i)
            flow = Flow(switch_id, i, id, priority, cfg.ns)
            flow.instructions([
                ['apply-actions', [{'action': [Flow.output_to_port('NORMAL')], 'order': 0, 'ns': 'f'}]]
            ], [0])
        tables[i]['flows'].append(flow)

    # push all flows

    for table in tables:
        for flow in table['flows']:
            code = cfg.push_flow(flow.switch, flow.body)
            if code != 0:
                print('Problems when pushing flow {0} to table {1}'.format(flow, table))

def forward_to_tunnel(cfg, pattern, iot_switch_id, table_id, priority, tunnel):

    pushed_flows = []
    ip_protocol, src, dst = src_dst_ips(pattern)
    src_mask = ip_mask(src)
    dst_mask = ip_mask(dst)

    # forward packets from outside

    id = 'table' + str(table_id) + '_forward_to_tunnel_' + pattern
    flow = Flow(iot_switch_id, table_id, id, priority, cfg.ns)
    f_match = [
        Flow.ethernet_type(2048),
        Flow.ip_protocol(ip_protocol),
        ['ipv4-source', dst_mask],
        ['ipv4-destination', src_mask]
    ]
    flow.match(f_match)
    flow.instructions([
        ['apply-actions', [
            {'action': [Flow.output_to_port(tunnel)], 'order': 0, 'ns': 'f'}
        ]]
    ], [0])
    cfg.push_flow(flow.switch, flow.body)
    pushed_flows.append({'node_id': iot_switch_id, 'table_id': table_id, 'flow_id': id})

    # if there is something coming from the tunnel we let it go:

    id = 'table' + str(table_id) + '_forward_from_tunnel_' + pattern
    bigger_priority = priority + 1
    flow = Flow(iot_switch_id, table_id, id, bigger_priority, cfg.ns)
    f_match = [
        Flow.in_port(tunnel),
        Flow.ethernet_type(2048),
        Flow.ip_protocol(ip_protocol),
        ['ipv4-source', src_mask],
        ['ipv4-destination', dst_mask]
    ]
    flow.match(f_match)
    flow.instructions([
        Flow.go_to_table(table_id + 1)
    ], [0])
    cfg.push_flow(flow.switch, flow.body)
    pushed_flows.append({'node_id': iot_switch_id, 'table_id': table_id, 'flow_id': id})

    return pushed_flows

def unforward_from_tunnel(cfg, pattern, iot_switch_id, table_id):
    removed_flows = []
    ids = [
        'table' + str(table_id) + '_forward_outgoing_to_tunnel_' + pattern,
        'table' + str(table_id) + '_forward_incoming_to_tunnel_' + pattern
    ]
    tables = [
        table_id,
        table_id
    ]
    for id, table_id in zip(ids, tables):
        cfg.delete_flow(iot_switch_id, table_id, id)
        removed_flows.append({'node_id': iot_switch_id, 'table_id': table_id, 'flow_id': id})
    return removed_flows

def forward_through_tunnel(cfg, pattern, iot_switch_id, table_id, priority, tunnel):

    print(tunnel)
    assert type(tunnel) is list
    pushed_flows = []
    ip_protocol, src, dst = src_dst_ips(pattern)
    src_mask = ip_mask(src)
    dst_mask = ip_mask(dst)

    # forward packets from outside

    id = 'table' + str(table_id) + '_forward_to_tunnel_' + pattern
    flow = Flow(iot_switch_id, table_id, id, priority, cfg.ns)
    f_match = [
        Flow.ethernet_type(2048),
        Flow.ip_protocol(ip_protocol),
        ['ipv4-source', dst_mask],
        ['ipv4-destination', src_mask]
    ]
    flow.match(f_match)
    flow.instructions([
        ['apply-actions', [
            {'action': [Flow.output_to_port(tunnel[0])], 'order': 0, 'ns': 'f'}
        ]]
    ], [0])
    cfg.push_flow(flow.switch, flow.body)
    pushed_flows.append({'node_id': iot_switch_id, 'table_id': table_id, 'flow_id': id})

    # if there is something coming from the tunnel we let it go:

    id = 'table' + str(table_id) + '_forward_from_tunnel_' + pattern
    bigger_priority = priority + 1
    flow = Flow(iot_switch_id, table_id, id, bigger_priority, cfg.ns)
    f_match = [
        Flow.in_port(tunnel[1]),
        Flow.ethernet_type(2048),
        Flow.ip_protocol(ip_protocol),
        ['ipv4-source', dst_mask],
        ['ipv4-destination', src_mask]
    ]
    flow.match(f_match)
    flow.instructions([
        Flow.go_to_table(table_id + 1)
    ], [0])
    cfg.push_flow(flow.switch, flow.body)
    pushed_flows.append({'node_id': iot_switch_id, 'table_id': table_id, 'flow_id': id})

    return pushed_flows

def mirror_to_tunnel(cfg, pattern, iot_switch_id, table_id, priority, ids_tunnel):

    pushed_flows = []
    ip_protocol, src, dst = src_dst_ips(pattern)
    src_mask = ip_mask(src)
    dst_mask = ip_mask(dst)

    # mirror outgoing packets

    id = 'table' + str(table_id) + '_mirror_outgoing_to_ids_' + pattern
    flow = Flow(iot_switch_id, table_id, id, priority, cfg.ns)
    f_match = [Flow.ethernet_type(2048), Flow.ip_protocol(ip_protocol), ['ipv4-source', src_mask], ['ipv4-destination', dst_mask]]
    flow.match(f_match)
    flow.instructions([
        Flow.go_to_table(table_id + 1),
        ['apply-actions', [
            {'action': [Flow.output_to_port(ids_tunnel)], 'order': 0, 'ns': 'f'}
        ]]
    ], [0, 1])
    cfg.push_flow(flow.switch, flow.body)
    pushed_flows.append({'node_id': iot_switch_id, 'table_id': table_id, 'flow_id': id})

    # mirror incoming packets

    id = 'table' + str(table_id) + '_mirror_incoming_to_ids_' + pattern
    flow = Flow(iot_switch_id, table_id, id, priority, cfg.ns)
    f_match = [Flow.ethernet_type(2048), Flow.ip_protocol(ip_protocol), ['ipv4-source', dst_mask], ['ipv4-destination', src_mask]]
    flow.match(f_match)
    flow.instructions([
        Flow.go_to_table(table_id + 1),
        ['apply-actions', [
            {'action': [Flow.output_to_port(ids_tunnel)], 'order': 0, 'ns': 'f'}
        ]]
    ], [0, 1])
    cfg.push_flow(flow.switch, flow.body)
    pushed_flows.append({'node_id': iot_switch_id, 'table_id': table_id, 'flow_id': id})

    return pushed_flows

def unmirror_from_tunnel(cfg, pattern, iot_switch_id, table_id):

    removed_flows = []
    ids = [
        'table' + str(table_id) + '_mirror_outgoing_to_ids_' + pattern,
        'table' + str(table_id) + '_mirror_incoming_to_ids_' + pattern,
    ]
    tables = [
        table_id,
        table_id
    ]
    for id, table_id in zip(ids, tables):
        cfg.delete_flow(iot_switch_id, table_id, id)
        removed_flows.append({'node_id': iot_switch_id, 'table_id': table_id, 'flow_id': id})
    return removed_flows

def block(cfg, pattern, iot_switch_id, table_id, priority, timeout=0):

    pushed_flows = []
    ip_protocol, src, dst = src_dst_ips(pattern)
    src_mask = ip_mask(src)
    dst_mask = ip_mask(dst)

    id = 'table' + str(table_id) + '_block_' + pattern
    flow = Flow(iot_switch_id, table_id, id, priority, cfg.ns, timeout)
    f_match = [
        Flow.ethernet_type(2048),
        Flow.ip_protocol(ip_protocol)
    ]
    if '*' not in src:
        f_match.append(['ipv4-source', src_mask])
    if '*' not in dst:
        f_match.append(['ipv4-destination', dst_mask])
    flow.match(f_match)
    flow.instructions([
        ['apply-actions', [
            {'action': [['drop-action', None]], 'order': 0, 'ns': 'f'}
        ]]
    ], [0])
    cfg.push_flow(flow.switch, flow.body)
    pushed_flows.append({'node_id': iot_switch_id, 'table_id': table_id, 'flow_id': id})

    return pushed_flows

def unblock(cfg, pattern, iot_switch_id, table_id):
    removed_flows = []
    ids = [
        'table' + str(table_id) + '_block_outgoing_' + pattern
    ]
    tables = [
        table_id
    ]
    for id,table_id in zip(ids, tables):
        cfg.delete_flow(iot_switch_id, table_id, id)
        removed_flows.append({'node_id': iot_switch_id, 'table_id': table_id, 'flow_id': id})
    return removed_flows

def remove_flows(cfg, flows):
    for flow in flows:
        cfg.delete_flow(flow['node_id'], flow['table_id'], flow['flow_id'])