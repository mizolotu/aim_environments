import pcap

from socket import inet_ntop, AF_INET
from threading import Thread
from queue import Queue
from time import time
from datetime import datetime
from kaitaistruct import KaitaiStream, BytesIO

from aim_environments.common.pkt_parse import EthernetFrame

class FlowMonitor():

    def __init__(self, flow_cbs, vnf_cbs, bridge_name='zero', time_threshold=0.1, auto_roll=False):
        self.name = bridge_name
        self.pkt_queue = Queue()
        self.flow_cbs = flow_cbs
        self.vnf_cbs = vnf_cbs
        self.threshold = time_threshold
        self.auto_roll = auto_roll

    def start(self):
        self.s_time = time()
        queue_td = Thread(target=self.queue_packets)
        queue_td.setDaemon(1)
        queue_td.start()
        if self.auto_roll:
            roll_td = Thread(target=self.process_packets)
            roll_td.setDaemon(1)
            roll_td.start()

    def process_vnf_signals(self):
        vnf_threads = []
        for item in self.vnf_cbs:
            cb = item['func']
            args = item['args']
            vnf_threads.append(Thread(target=cb, args=args))
        for t in vnf_threads:
            t.start()
        for t in vnf_threads:
            t.join()

    def queue_packets(self):
        sniffer = pcap.pcap(name=self.name, timeout_ms=10)
        while True:
            ts, pkt = next(sniffer)
            self.pkt_queue.put((ts, pkt))

    def process_packets(self):
        count = 0
        while True:
            start_time = self.s_time + count * self.threshold
            packets = []
            timestamp = str(datetime.now().timestamp())
            while True:
                t_now = str(datetime.now().timestamp())
                try:
                    timestamp, raw = self.pkt_queue.get()
                    pkt = EthernetFrame(KaitaiStream(BytesIO(raw)))
                    if pkt.ether_type.value == 2048:
                        src_ip = inet_ntop(AF_INET, pkt.body.src_ip_addr)
                        dst_ip = inet_ntop(AF_INET, pkt.body.dst_ip_addr)
                        flags = 0
                        payload = ''
                        proto = str(pkt.body.protocol)
                        pkt_size = pkt.body.total_length
                        if proto in ['6', '17']:
                            src_port = str(pkt.body.body.body.src_port)
                            dst_port = str(pkt.body.body.body.dst_port)
                            if proto == '6':
                                flags = pkt.body.body.body.b13
                                body = pkt.body.body.body.body
                                decoded = body.decode('ascii','ignore')
                                if '80' in [src_port, dst_port] and ('\\r\\n' in decoded or '\r\n' in decoded):
                                    payload = ','.join([str(b) for b in body])
                                elif '22' in [src_port, dst_port] and 'SSH-' in decoded:
                                    payload = body
                            elif proto == '17' and '53' in [src_port, dst_port]:
                                body = pkt.body.body.body.body
                                payload = ','.join([str(b) for b in body])
                            fields = [
                                timestamp,
                                src_ip,
                                src_port,
                                dst_ip,
                                dst_port,
                                proto,
                                pkt_size,
                                flags,
                                payload
                            ]
                            packets.append(fields)
                except Exception as e:
                    print(body)
                    print(e)
                thr = start_time + self.threshold
                if float(timestamp) > thr or (self.pkt_queue.qsize() == 0 and float(t_now) > thr):
                    break

            # process flow callback

            q_size = self.pkt_queue.qsize()
            count += 1
            for item in self.flow_cbs:
                cb = item['func']
                args = item['args']
                cb(packets, q_size, *args)

            # process vnf callbacks

            self.process_vnf_signals()

            # break if one loop flag is true

            if self.auto_roll:
                with self.pkt_queue.mutex:
                    self.pkt_queue.queue.clear()
            else:
                break