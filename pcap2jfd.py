#!/usr/bin/python2.7

from optparse import OptionParser
import socket
import struct
import dpkt
import json


debug = False

def dprint(string):
    global debug
    if debug: print string

class Connection:
    def __init__(self, src_ip, dst_ip, sport, dport):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.sport = sport
        self.dport = dport

        self.is_client = None
        # self.rtt = .001 # 10 milliseconds
        self.rtt = .1 # 1 second
        self.index = 0
        self.tx_last_seq = 0
        self.tx_next_seq = 0
        self.rx_last_seq = 0
        self.rx_next_seq = 0

        self.last_time = None
        self.last_size = None
        self.last_dir = "None"

        self.sizes = []
        self.times = []
        self.dirs = []
        self.seq = []

    def packet_is_continuation(self, ts, pktlen, origin):
        is_continuation = True
        if (origin):
            dir = ">"
        else:
            dir = "<"
        dprint("-------------------------------------------------")
        dprint(dir)
        
        if self.last_size == None:
            dprint("first packet in flow")
            is_continuation = False
        elif dir != self.last_dir:
            dprint("reversed direction")
            is_continuation = False
            
        if ts - self.last_time >= self.rtt:
            dprint("not within one RTT (delta=" + str(1000*(ts-self.last_time)) +"ms)")
            is_continuation = False

        if is_continuation:
            dprint("continuation")
            if self.last_size != pktlen:
                dprint("note: " + str(self.last_size) + " != " + str(pktlen))
        else:
            dprint("not continuation")
        return is_continuation


class PCAP2SALT:
    def __init__(self, ifile, ofile, aggregate=False, labels=None, logfile=None):
        self.ifile = ifile
        self.ofile = ofile
        self.aggregate = aggregate
        self.labels = labels
        self.logfile = logfile

    def parse(self):
        connections = {}
        MAXLEN = 50

        # used for logging, probably a cleaner way to do this, but I wanted some flexibility
        log = {}
        log['num_out_of_order_tx'] = 0
        log['num_out_of_order_rx'] = 0
        log['num_exceeded_max_len'] = 0
        log['num_inbound_have_tsval'] = 0
        log['num_outbound_have_tsval'] = 0
        log['num_non_ignored_packets'] = 0
        log['num_total_packets'] = 0
        log['num_total_flows'] = 0

        f = open(self.ifile)
        try:
            pcap = dpkt.pcap.Reader(f)
        except:
            print 'fail'
            return

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            try:
                tcp = ip.data
            except:
                continue

            if type(eth.data) == dpkt.arp.ARP:
                continue
            if type(tcp) == dpkt.icmp.ICMP or type(tcp) == dpkt.igmp.IGMP:
                continue

            if type(tcp) != dpkt.udp.UDP and type(tcp) != dpkt.tcp.TCP:
                continue

            if type(tcp) == dpkt.udp.UDP:
                t = 'udp'
            elif type(tcp) == dpkt.tcp.TCP:
                t = 'tcp'

            # special parsing for ipv4/ipv6
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                src_ip = socket.inet_ntop(socket.AF_INET,ip.src)
                dst_ip = socket.inet_ntop(socket.AF_INET,ip.dst)
            elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
                src_ip = socket.inet_ntop(socket.AF_INET6,ip.src)
                dst_ip = socket.inet_ntop(socket.AF_INET6,ip.dst)
            else:
                # weird error
                continue

            sport = tcp.sport
            dport = tcp.dport

            key1 = src_ip + '_' + dst_ip + '_' + str(sport) + '_' + str(dport) + '_' + t
            key2 = dst_ip + '_' + src_ip + '_' + str(dport) + '_' + str(sport) + '_' + t
            if key1 not in connections and key2 not in connections:
                if t == 'tcp' and tcp.flags & dpkt.tcp.TH_SYN:
                    conn = Connection(src_ip, dst_ip, sport, dport)
                    connections[key1] = conn
                    conn.last_time = ts
                elif t == 'udp':
                    # NYI
                    continue
#                    conn = Connection(src_ip, dst_ip, sport, dport)
#                    connections[key1] = conn
#                    conn.last_time = ts

            else:
                if key1 in connections:
                    key = key1
                    origin = True
                else:
                    key = key2
                    origin = False
                conn = connections[key]
                pktlen = len(tcp.data)
                if t == 'tcp':

                    if origin:
                        for (o,d) in dpkt.tcp.parse_opts(tcp.opts):
                            if o == dpkt.tcp.TCP_OPT_TIMESTAMP:
                                print struct.unpack('>II', d)
                                log['num_outbound_have_tsval'] += 1
                    else:
                        for (o,d) in dpkt.tcp.parse_opts(tcp.opts):
                            if o == dpkt.tcp.TCP_OPT_TIMESTAMP:
                                print struct.unpack('>II', d)
                                log['num_inbound_have_tsval'] += 1

                    if pktlen > 0:
                        log['num_total_packets'] += 1
                        TLSRecordLengths = self.parseTLSRecordLength(tcp.data)
#                        print TLSRecordLengths

                        # print "SEQ: " + str(tcp.seq)
                        # print "ACK: " + str(tcp.ack)

                        if conn.index == 0:
                            conn.sizes.append(pktlen)
                            conn.times.append(0)
                            if origin:
                                conn.dirs.append('>')
                            else:
                                conn.dirs.append('<')
                            conn.index += 1
                            conn.last_time = ts
                            conn.tx_last_seq = tcp.seq
                            conn.tx_next_seq = tcp.seq + pktlen
                        else:
                            ignore = False
                            if origin:
                                if tcp.seq <= conn.tx_last_seq:
                                    log['num_out_of_order_tx'] += 1
                                if tcp.seq == conn.tx_last_seq:
                                    if tcp.seq + pktlen <= conn.tx_next_seq:
                                        ignore = True
                                    else:
                                        new_pktlen = (tcp.seq + pktlen) - conn.tx_next_seq
                                        seq = conn.tx_next_seq
                                        pktlen = new_pktlen
                                elif pktlen == 1 and tcp.seq == conn.tx_next_seq - 1:
                                    ignore = True
                            else:
                                if tcp.seq <= conn.rx_last_seq:
                                    log['num_out_of_order_rx'] += 1
                                if tcp.seq == conn.rx_last_seq:
                                    if tcp.seq + pktlen <= conn.rx_next_seq:
                                        ignore = True
                                    else:
                                        new_pktlen = (tcp.seq + pktlen) - conn.rx_next_seq
                                        seq = conn.rx_next_seq
                                        pktlen = new_pktlen
                                elif pktlen == 1 and tcp.seq == conn.rx_next_seq - 1:
                                    ignore = True
                            if not ignore:
                                if conn.index == 1:
                                    log['num_total_flows'] += 1
                                # print "connection " + str(key)
                                if conn.packet_is_continuation(ts, pktlen, origin):
                                    if self.aggregate:
                                        if conn.index < MAXLEN-1:
                                            conn.sizes[conn.index-1] += pktlen
                                            # print "aggregate length: " + str(conn.sizes[conn.index-1])
                                            # if conn.sizes[conn.index-1] > 0xffff - pktlen:
                                            #    print "warning: aggregated message length exceeds 65,536"

                                        else:
                                            dprint("hit MAXLEN when aggregating")
                                    else:
                                        if conn.index < MAXLEN-1:
                                            log['num_non_ignored_packets'] += 1
                                            conn.sizes.append(pktlen)
                                            conn.times.append(ts - conn.last_time)
                                            if origin:
                                                conn.dirs.append('>')
                                            else:
                                                conn.dirs.append('<')
                                            conn.index += 1
                                        else:
                                            if conn.index == MAXLEN-1:
                                                log['num_exceeded_max_len'] += 1
                                                conn.index += 1
                                else:
                                    if conn.index < MAXLEN-1:
                                        log['num_non_ignored_packets'] += 1
                                        conn.sizes.append(pktlen)
                                        conn.times.append(ts - conn.last_time)
                                        if origin:
                                            conn.dirs.append('>')
                                        else:
                                            conn.dirs.append('<')
                                        conn.index += 1
                                    else:
                                        if conn.index == MAXLEN-1:
                                            log['num_exceeded_max_len'] += 1
                                            conn.index += 1
                                if origin:
                                    conn.tx_last_seq = tcp.seq
                                    conn.tx_next_seq = tcp.seq + pktlen
                                else:
                                    conn.rx_last_seq = tcp.seq
                                    conn.rx_next_seq = tcp.seq + pktlen

                                conn.last_time = ts
                                if origin:
                                    conn.last_dir = ">"
                                else:
                                    conn.last_dir = "<"
                                conn.last_size = pktlen

        f.close()

        flows = {}
        flows['appflows'] = []
        num_conns = 0
        for key in connections:
#            print key
            num_conns += 1
            conn = connections[key]
            flow = {}
            if (self.labels != None):
                for label in self.labels.split(","):
                    x = label.split("=")
                    print x
                    flow[x[0]] = x[1]
            flow["sa"] = conn.src_ip
            flow["da"] = conn.dst_ip
            flow["sp"] = conn.sport
            flow["dp"] = conn.dport
            flow["non_norm_stats"] = []
            conns = zip(conn.sizes, conn.times, conn.dirs)
            ob = 0
            ib = 0
            ip = 0
            op = 0
            for (s,t,d) in conns:
                tmp = {}
                tmp["b"] = s
                tmp["ipt"] = int(t*10000)
                tmp["dir"] = d
                if d == '<':
                    ip += 1
                    ib += s
                else:
                    op += 1
                    ob += s
                flow["non_norm_stats"].append(tmp)
            flow["ob"] = ob
            flow["ib"] = ib
            flow["op"] = op
            flow["ip"] = ip
            flows['appflows'].append({"flow":flow})

        f = open(self.ofile,'wb')
        json.dump(flows, f, indent=4, separators=(',', ': '))
        f.close()

        if self.logfile != None:
            with open(self.logfile,'a') as fp:
                fp.write('Number of out of order tx packets:\t' + str(log['num_out_of_order_tx']) + '\n')
                fp.write('Number of out of order rx packets:\t' + str(log['num_out_of_order_rx']) + '\n')
                fp.write('Number of flows that exceeded the max length:\t' + str(log['num_exceeded_max_len']) + '\n')
                fp.write('Number of inbound flows with tsval:\t' + str(log['num_inbound_have_tsval']) + '\n')
                fp.write('Number of outbound flows with tsval:\t' + str(log['num_outbound_have_tsval']) + '\n')
                fp.write('Number of non ignored packets:\t' + str(log['num_non_ignored_packets']) + '\n')
                fp.write('Number of total packets:\t' + str(log['num_total_packets']) + '\n')
                fp.write('Number of total flows:\t' + str(log['num_total_flows']) + '\n')
                fp.write('\n')

    def parseTLSRecordLength(self, tcpdata):
        if len(tcpdata) < 5:
            return []

        if int(tcpdata[1:2].encode('hex'),16) == 3:
            lenField = [int(tcpdata[3:5].encode('hex'),16)]
            recordLengths = self.parseTLSRecordLength(tcpdata[5+lenField[0]:])
            lenField.extend(recordLengths)
            return lenField
        else:
            return []


if __name__ == "__main__":
    parser = OptionParser()
    parser.set_description("convert pcap file to flow metadata in json format")
    parser.add_option("-i", "--ifile", help="input file (pcap)")
    parser.add_option("-o", "--ofile", help="output file (json)")
    parser.add_option("-a", "--aggregate", dest="aggregate", action="store_true",
                      default=False, help="aggregate TCP message lengths across packets ")
    parser.add_option("-l", "--labels", dest="labels", help="add labels a=<A>,b=<B>,... to each flow") 
    parser.add_option("-e", "--exehash", dest="exehash", action="store_true", 
                      default=False, help="add label hs=<fileprefix> to each flow") 
    parser.add_option("-s", "--samplehash", dest="samplehash", action="store_true", 
                      default=False, help="add label ms=<fileprefix> to each flow") 
    parser.add_option("-w", "--lfile", help="log useful information to specified file") 
    
    (opts, args) = parser.parse_args()

    got_needed_args = True
    if (opts.ifile == None):
        print "error: missing input file (-i or --ifile argument required)"
        got_needed_args = False
    if (opts.ofile == None):
        print "error: missing output file (-o or --ofile argument required)"
        got_needed_args = False    
    if (not got_needed_args):
        parser.print_help()
        exit()

    infile_name = opts.ifile.split(".")
    infile_prefix = str(infile_name[0])

    if (opts.labels != None):
        try:
            for label in opts.labels.split(","):
                x = label.split("=")
                assert(len(x) == 2),   "wrong syntax in label argument" 
                assert(len(x[0]) > 0), "wrong syntax in label argument"
                assert(len(x[1]) > 0), "wrong syntax in label argument"
        except:
            print "error: cannot parse the argument to -l (" + str(opts.labels) + ")"
            exit()

    if (opts.exehash == True):
        if opts.labels == None:
            opts.labels = ""
        else:
            opts.labels = opts.labels + ","
        opts.labels += ("hs=" + infile_prefix)

    if (opts.samplehash == True):
        if (opts.exehash == True):
            print "error: both -e and -s specified (only one may be used at a time)"
            exit()
        if opts.labels == None:
            opts.labels = ""
        else:
            opts.labels = opts.labels + ","
        opts.labels += ("ms=" + infile_prefix)

    p = PCAP2SALT(opts.ifile, opts.ofile, opts.aggregate, opts.labels, opts.lfile)
    p.parse()

