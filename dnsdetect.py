#! /usr/bin/python
import os 
from scapy.all import *
import sys
import netifaces as ni
from netifaces import AF_INET, AF_INET6
import getopt
 
data = dict()

def get_ip_address(ifname = None):
        intflist = ni.interfaces()      
        for intf in intflist:
            try:
                iaddr = netifaces.ifaddresses(intf)[AF_INET][0]['addr']
                if "127.0.0.1" not in iaddr:
                    return iaddr
            except: pass
        return ""
            

def detect(pkt):
        global data
        if IP in pkt:
		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                        key = (pkt[IP].src,pkt[IP].dport,pkt[IP].sport,pkt[DNS].id,pkt[DNS].qd.qname)
			data[key]=None
		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 1:
                        try:
                            key = (pkt[IP].dst,pkt[IP].sport,pkt[IP].dport,pkt[DNS].id,pkt[DNS].qd.qname)
                        except:
                            return
                        rdataList = []
                        for i in range(pkt[DNS].ancount):
                            if pkt[DNS].an[i].type == 1: #A Type
                                rdataList.append(pkt[DNS].an[i].rdata)
                        srdataList = sorted(rdataList)
                        try:
			    if key not in data or data[key]==None:
			        data[key]=(rdataList,pkt[DNSRR].ttl)
		            elif sorted(data[key][0])==srdataList or (sorted(data[key][0])!=srdataList and data[key][1]==pkt[DNSRR].ttl): pass
			        #print 'Retransmission!'
			    else:
		                print '****************************************************************'
				print time.strftime("%Y-%m-%d %H:%M"),'DNS Poisoning Attempt'
				print 'TXID',hex(int(pkt[DNS].id)),'Request',pkt.getlayer(DNS).qd.qname
				print 'Answer1',data[key][0]
				print 'Answer2',rdataList
				del data[key]
				print '****************************************************************'
                        except:
                                try:
				    print '****************************************************************'
                                    print ';; ANSWER SECTION: in packet not found! No DNSRR Record'
				    print time.strftime("%Y-%m-%d %H:%M"),'DNS Poisoning Attempt'
				    print 'TXID',hex(int(pkt[DNS].id)),'Request',pkt.getlayer(DNS).qd.qname
				    print 'Answer1',data[key][0]
				    print 'Answer2',rdataList
				    del data[key]
				    print '****************************************************************'
                                except: return

def main():
    global hostnamesDict
    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:r:")
    except getopt.GetoptError as err:
        # print help information and exit:
        print str(err)  # will print something like "option -a not recognized"
        sys.exit(2)
    interface = None
    tracefile = None
    expression = ''
    for o, a in opts:
        if o == "-i":
            interface = a
        elif o == "-r":
            tracefile = a
        else:
            assert False, "unhandled option"
    if len(args)==1:
        expression = args[0] 
    print "Interface:",interface,"Tracefile:",tracefile,"Expression:",expression
    if interface!=None and tracefile!=None:
        print "Please provide either interface or tracefile. Exiting"
        sys.exit()
    
    if interface!=None:
        print "Sniffing on Interface:",interface
        sniff(iface = interface,filter = expression, prn = detect, store = 0)
    elif tracefile!=None:
        print "Sniffing from Tracefile:",tracefile
        sniff(offline = tracefile,filter = expression, prn = detect, store = 0)
    else:
        sniff(filter = expression, prn = detect, store = 0)

if __name__ == "__main__":
    main()
