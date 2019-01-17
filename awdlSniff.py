#!/usr/bin/env python2.7
from __future__ import print_function
from datetime import datetime
import traceback
import time
from scapy.all import *

myiface = "awdl0"
mymac = get_if_hwaddr(myiface)
myip6 = get_if_addr6(myiface) # Not working

identities = {}
identities["<EXAMPLE>"] = {"ipv6" : "ff02:ab:ba:ab:ba:ff", "lastseen": "1970-01-01T00:00.00", "PTR": ["abbaabba", "_notreal"]}
## Create a Packet Counter
counter = 0

# Enable colors

TXTRED = '\033[0;31m'  # Red
TXTGRN = '\033[0;32m'  # Green
TXTYLW = '\033[0;33m'  # Yellow
TXTBLU = '\033[0;34m'  # Blue
TXTPUR = '\033[0;35m'  # PUR ple
TXTCYN = '\033[0;36m'  # Cyan
TXTWHT = '\033[0;37m'  # White

BLDBLK = '\033[1;30m'  # Black - Bold
BLDRED = '\033[1;31m'  # Red
BLDGRN = '\033[1;32m'  # Green
BLDYLW = '\033[1;33m'  # Yellow
BLDBLU = '\033[1;34m'  # Blue
BLDPUR = '\033[1;35m'  # PUR ple
BLDCYN = '\033[1;36m'  # Cyan
BLDWHT = '\033[1;37m'  # White

UNDBLK = '\033[4;30m'  # Black - UNDerline
UNDRED = '\033[4;31m'  # Red
UNDGRN = '\033[4;32m'  # Green
UNDYLW = '\033[4;33m'  # Yellow
UNDBLU = '\033[4;34m'  # Blue
UNDPUR = '\033[4;35m'  # PUR ple
UNDCYN = '\033[4;36m'  # Cyan
UNDWHT = '\033[4;37m'  # White

BAKBLK = '\033[40m'   # Black - BackgroUND
BAKRED = '\033[41m'   # Red
BAKGRN = '\033[42m'   # Green
BAKYLW = '\033[43m'   # Yellow
BAKBLU = '\033[44m'   # Blue
BAKPUR = '\033[45m'   # PUR ple
BAKCYN = '\033[46m'   # Cyan
BAKWHT = '\033[47m'   # White

TXTRST = '\033[0m'    # Text Reset

def convertType(qtype):
    if qtype == 12:
        dtype = "PTR" 
    elif qtype == 16:
        dtype = "TXT"
    elif qtype == 33:
        dtype = "SRV"
    elif qtype == 28:
        dtype = "AAAA"
    else:
        dtype = "Unknown(%s)" % qtype
    
    return dtype

def parse_dnspkt(pkt):
    """ parse dns request / response packet """
    rawpayload = False
    if pkt and pkt.haslayer(Raw):
        rawpayload = str(pkt[Raw].load)[13:23]
    ipsrc = None
    ipdst = None
    udp = pkt['UDP']

    if pkt and pkt.haslayer(UDP) and pkt.haslayer(DNS):
        ipsrc = "none"
        ipdst = "none"
        if pkt.haslayer(IP):
            ip = pkt['IP']
            ipsrc = ip.src
            ipdst = ip.dst
        elif pkt.haslayer(IPv6):
            ip = pkt['IPv6']
            ipsrc = ip.src
            ipdst = ip.dst

        dns = pkt['DNS']

        # mdns query packet
        query = ""
        answer = ""
        additionalrecord = ""
        anrrname = "none"
        anrdata = "none"
        rawpayload = ""
        answers = ""
        debug = ""
        # If there is query 
        if dns.qdcount >= 1:
            qname = dns.qd.qname

        # If there is answers
        ars = ""                                                  
        if dns.ancount >= 1:
            for count in range(0, dns.ancount):
                an = dns.an[count]
                if an.haslayer(DNSRR): 
                    dtype = convertType(an.type)
                    
                    if an.type == 28:
                        lastseen = datetime.now().replace(microsecond=0).isoformat()
                        if not an.rrname in identities:
                            identities[an.rrname] = { "ipv6": an.rdata, "lastseen": lastseen, }

                        identities[an.rrname].update({ "ipv6": an.rdata, "lastseen": lastseen, })
                        if not 'PTR' in identities[an.rrname]:
                            identities[an.rrname]["PTR"] = []

                        # Loop other answer sections to find more information (PTR records) 
                        for c in range(0, dns.ancount):
                            loopan = dns.an[c]
                            if loopan.type == 12:
                                if loopan.rdata not in identities[an.rrname]["PTR"] and not loopan.rdata is an.rrname:
                                    identities[an.rrname]["PTR"].append(loopan.rdata)

                            
            
        
        # If there is additinal records
        if dns.arcount >= 1:
            for count in range(0, dns.arcount):
                ar = dns.ar[count]
                if ar.haslayer(DNSRR): 
                    dtype = convertType(an.type)
             

    # If everything else fails, lets return some information
    m = "Cant parse: %s" % pkt.summary()
    return m

def clearscreen():
    return "\x1b" + "[2J"
  
def render():
    m = "%s%smdnsSniff %scount: %s%s\n" % (clearscreen(),BLDRED, BLDGRN, len(identities), TXTRST)
    m = m + "" 
    
    for i in identities:
        m = "%s %s%s%s> %s%s%s IPv6: %s%s%s PTR: %s%s%s\n" % (m, 
                                                BLDBLU, identities[i]["lastseen"], TXTRST,
                                                BLDPUR, i, TXTRST,
                                                BLDGRN, identities[i]["ipv6"], TXTRST,
                                                BLDYLW, identities[i]["PTR"], TXTRST
                                                )
    return m
        
## Define our Custom Action function
def print_action(packet):
    global counter
    counter += 1
    payload = "No Raw payload"
    m = "<empty m>"
    try:
        payload = parse_dnspkt(packet)

    except:
        return "{}Error:{} {} Traceback: {}".format(TXTRED, TXTRST, packet[0][1].summary, traceback.print_exc(file=None))   

    #m = ">> {}{}{}{}\n>>{}{}{}\n".format(TXTYLW, "de: ", packet[0][1].summary, TXTRST, TXTGRN, payload, TXTRST) 
    #m = ">> {}{}{}{}".format( TXTRST, TXTGRN, payload, TXTRST) 
    m = render()
    return m

## Setup sniff, filtering for IP traffic
print("Waiting first packets to arrive...")
sniff(filter="udp and port 5353", prn=print_action, iface=myiface )

