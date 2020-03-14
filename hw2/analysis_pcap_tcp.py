#!/bin/python

import dpkt
import sys, datetime, socket
from datetime import datetime, timedelta

USAGE = "USAGE:\tanalysis_pcap_tcp.py <PCAP FILE>"
SRC_IP = "130.245.145.12" 
DST_IP = "128.208.2.198"

def map_flow(pcap):
    flow_dict = {}
    total_flows = 0
    for t, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if (eth.data.p != dpkt.ip.IP_PROTO_TCP):
            continue
        src = socket.inet_ntoa(eth.ip.src)
        dst = socket.inet_ntoa(eth.ip.dst)
        tcp = eth.ip.data
        syn = (tcp.flags & dpkt.tcp.TH_SYN) != 0
        ack = (tcp.flags & dpkt.tcp.TH_ACK) != 0
        fin = (tcp.flags & dpkt.tcp.TH_FIN) != 0
        pkt_dict = {
            'syn': syn, 'ack': ack, 'fin': fin,
            'src': socket.inet_ntoa(eth.ip.src), 'dst': socket.inet_ntoa(eth.ip.dst),
            'tcp': eth.ip.data,
            'timestamp': t
        }
        if (src == SRC_IP and dst == DST_IP):
            if (syn):
                total_flows += 1
                syn_dict = {
                    'flow_start': t, 
                    'flow': [pkt_dict],
                    'scale': tcp.opts[-1],
                    'iseq': tcp.seq
                }
                if (flow_dict.get(tcp.sport, False)):
                    flow_dict[tcp.sport].append(syn_dict)
                else:
                    flow_dict[tcp.sport] = [syn_dict]
            else:        
                if (flow_dict.get(tcp.sport, False)):
                    syn_dict = max(flow_dict[tcp.sport], key=lambda x: x['flow_start'])
                    syn_dict['flow'].append(pkt_dict)
        elif (src == DST_IP and dst == SRC_IP):
            if (flow_dict.get(tcp.dport, False)):
                syn_dict = max(flow_dict[tcp.dport], key=lambda x: x['flow_start'])
                if (not syn_dict.get('iack', False)):
                    syn_dict['iack'] = tcp.seq
                syn_dict['flow'].append(pkt_dict)
    flow_lst = []
    for f in flow_dict.values():
        flow_lst.extend(f)
    return sorted(flow_lst, key=lambda f:f['flow_start']), total_flows

def analyze(pcap, max_pkt_per_flow=2, max_cwnd_rtt_count=5):
    """Print out information about each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    TCP_FLOWS_T = map_flow(pcap)
    print("\nTotal TCP Flows: %s\n" % TCP_FLOWS_T[1])
    for flow in TCP_FLOWS_T[0]:
        setup = 0
        src_c = 0
        dst_c = 0
        total_data = 0
        cwnd_i = 0
        cwnd_lst = [0] * max_cwnd_rtt_count
        pkt_buf = []
        start_time = datetime.fromtimestamp(flow['flow_start'])
        sorted_flows = sorted(flow['flow'], key=lambda x: x['timestamp'])
        for ip in sorted_flows:
            src = ip['src']
            dst = ip['dst']
            tcp = ip['tcp']
            syn = ip['syn']
            ack = ip['ack']
            fin = ip['fin']
            rwnd = tcp.win << flow['scale']
            if (src == SRC_IP and dst == DST_IP):
                if syn:
                    print("\n--- Start flow %s:%s -> %s:%s ---\n" % (src, tcp.sport, dst, tcp.dport))
                    setup += 1
                elif ack and not fin:
                    if setup == 2:
                        setup += 1
                    elif setup == 3:
                        if (src_c < max_pkt_per_flow):
                            print("%s:%s -> %s:%s\n[SEQ=%s (Relative=%s), ACK=%s (Relative=%s), RWND=%s]\n" % (
                                src, tcp.sport, dst, tcp.dport,
                                tcp.seq,
                                tcp.seq - flow['iseq'],
                                tcp.ack,
                                tcp.ack - flow['iack'],
                                rwnd
                            ))
                            src_c += 1
                        total_data += int(len(tcp.data) + (tcp.off/4))
                        if (cwnd_i < max_cwnd_rtt_count):
                            pkt_buf.append(tcp.seq + len(tcp.data))
                    else:
                        print("\n--- End flow (Handshake didn't finish) ---\n")
                elif fin:
                    print("\nTotal data sent: %s bytes" % total_data)
                    end_time = datetime.fromtimestamp(sorted_flows[-1]['timestamp'])
                    delta = ((end_time - start_time) / timedelta(milliseconds=1))
                    print("Total time between first byte and last ack: %.2f ms" % delta)
                    print("Sender throughput: %.2f bytes/ms" % (total_data/delta))
                    
                    for i, c in enumerate(cwnd_lst):
                        print("Size of cwnd %s: %s packets" % (i+1, cwnd_lst[i]))
                    
                    print("\n--- End flow %s:%s -> %s:%s ---\n" % (src, tcp.sport, dst, tcp.dport))
                    break         
            elif (src == DST_IP and dst == SRC_IP):
                if syn:
                    setup += 1
                elif ack:
                    if (dst_c < max_pkt_per_flow):
                        print("%s:%s <- %s:%s\n[SEQ=%s (Relative=%s), ACK=%s (Relative=%s), RWND=%s]\n" % (
                            dst, tcp.dport, src, tcp.sport,
                            tcp.seq,
                            tcp.seq - flow['iack'],
                            tcp.ack,
                            tcp.ack - flow['iseq'],
                            rwnd
                        ))
                        dst_c += 1
                    if (cwnd_i < max_cwnd_rtt_count):
                        buf_size = len(pkt_buf)
                        pkt_buf = list(filter(lambda x: x > tcp.ack, pkt_buf))
                        cwnd_lst[cwnd_i] = (
                            buf_size 
                            if ((cwnd_i == 0) or (buf_size > cwnd_lst[cwnd_i-1]))
                            else cwnd_lst[cwnd_i-1]
                        )
                        cwnd_i += 1 
        else:
            continue

if __name__ == "__main__":
    if (len(sys.argv) != 2):
        print(USAGE)
        exit(0)
    f = open(sys.argv[1], "rb")
    pcap = None
    try:
        pcap = dpkt.pcap.Reader(f)
    except:
        print("ERROR: Invalid pcap file (%s)" % sys.argv[1])
        exit(0)
    analyze(pcap)