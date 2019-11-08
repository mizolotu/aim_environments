import random

def get_random_mac():
    rnd_mac = "52:54:00:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    )
    rnd_mac_hex = '0x' + ''.join(rnd_mac.split(':'))
    return rnd_mac, rnd_mac_hex

def encode_ip_as_mac(ip_octets):
    mac_str = "52:54:" + ':'.join(['%02x' % (int(octet)) for octet in ip_octets])
    mac_hex = '0x' + ''.join(mac_str.split(':'))
    return mac_str, mac_hex

def ip_protocol_name(proto):
    name = ''
    if proto == '1':
        name = 'icmp'
    elif proto == '6':
        name = 'tcp'
    elif proto == '17':
        name = 'udp'
    return name

def ip_protocol_id(proto):
    id = '*'
    if proto.lower() == 'icmp':
        id = 1
    elif proto.lower() == 'tcp':
        id = 6
    elif proto.lower() == 'udp':
        id = 17
    return id

def ip_mask(ip_pattern):
    mask = 32 - 8 * ip_pattern.count('*')
    ip = ip_pattern.replace('*','0')
    return '{0}/{1}'.format(ip,mask)

def subnet(net_start, net_mask=24):
    if net_mask == 24:
        subnet = '{0}.0/24'.format('.'.join(net_start.split('.')[:-1]))
    elif net_mask == 16:
        subnet = '{0}.0.0/16'.format('.'.join(net_start.split('.')[:-2]))
    return subnet

def gateway(net_start):
    gateway = '{0}.1'.format('.'.join(net_start.split('.')[:-1]))
    return gateway

def ip_range(net_start, n):
    first_3_octets = '.'.join(net_start.split('.')[:-1])
    last_octet = int(net_start.split('.')[-1])
    ips = ['{0}.{1}'.format(first_3_octets, last_octet + i) for i in range(n)]
    return ips

def protocol_number(str):
    number = 0
    if str.lower() == 'icmp':
        number = '1'
    elif str.lower() == 'tcp':
        number = '6'
    elif str.lower() == 'udp':
        number = '17'
    return number

def decode_tcp_flags_value(value, n_flags=5):
    b = '{0:b}'.format(value)[::-1]
    positions = [i for i in range(len(b)) if b[i] == '1']
    return positions

def flow_pattern(proto, local_ip, remote_socket):
    fp = '{0}.{1}.*.{2}'.format(proto, local_ip, remote_socket)
    return fp

def src_dst_pattern(proto, local_ip, remote_ip):
    fp = '{0}.{1}.{2}'.format(proto, local_ip, remote_ip)
    return fp

def flow_ips(pattern):
    spl = pattern.split('.')
    src = '.'.join(spl[1:5])
    dst = '.'.join(spl[6:10])
    return src, dst

def src_dst_ips(pattern):
    spl = pattern.split('.')
    proto = spl[0]
    src = '.'.join(spl[1:5])
    dst = '.'.join(spl[5:9])
    return proto, src, dst

def flow_follows_pattern(flow, patterns):
    idx = -1
    found = [i for i in range(len(patterns)) if patterns[i] == flow]
    if found:
        idx = found[0]
    return idx