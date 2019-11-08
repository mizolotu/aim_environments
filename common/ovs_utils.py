from subprocess import Popen, PIPE

def get_iface_ofport(iface):
    p = Popen(['ovs-vsctl', 'get', 'interface', iface, 'ofport'], stdout=PIPE)
    ofport = p.stdout.read().decode('utf-8').strip()
    return ofport

def clean_ovs_ports():
    p = Popen(['ovs-vsctl', 'list-br'], stdout=PIPE)
    switches = p.stdout.read().decode('utf-8').strip().split('\n')
    ovs = {}
    for switch in switches:
        ovs[switch] = {}
        p = Popen(['ovs-vsctl', 'list-ifaces', switch], stdout=PIPE)
        ifaces = p.stdout.read().decode('utf-8').strip().split('\n')
        ifaces.append(switch)
        for iface in ifaces:
            if iface:
                p = Popen(['ovs-vsctl', 'get', 'interface', iface, 'type', 'mac_in_use', 'ofport', 'error'], stdout=PIPE)
                data = p.stdout.read().decode('utf-8').strip().split('\n')
                if '(No such device)' in data[3]:
                    Popen(['ovs-vsctl', 'del-port', switch, iface], stdout=PIPE).wait()
                else:
                    ovs[switch][iface] = {
                        'type': data[0],
                        'mac': data[1][1:-1],
                        'port': data[2]
                    }
    return ovs

def push_output_normal(switch_name, table=0,priority=0):
    flow_str = 'table={0},priority={1},action=output:NORMAL'.format(table, priority)
    Popen(['ovs-ofctl','add-flow',switch_name,flow_str]).wait()