#!/usr/bin/env python

import sys
import socket
import random
import struct

from scapy.all import *

def Main():

    if len(sys.argv)<3:
        print "pass 2 arguments, <destination> <message>"

    addr = socket.gethostbyname(sys.argv[1])
    try:
        iface = [i for i in get_if_list() if 'eth0' in i]
    except:
        print "Cannot find the interface"

    print "Sending on interface %s ot %s " %(iface, str(addr))
    
    pkt = Ether(src=get_if_hwaddr(iface[0]), dst="ff:ff:ff:ff:ff:ff")
    pkt = pkt / IP(dst=addr) / TCP(dport=12345, sport=random.randint(49000, 65535)) / sys.argv[2]        # sys.argv[2] is the payload
    pkt.show2()
    sendp(pkt, iface=iface[0], verbose=False)


if __name__ == '__main__':
    Main()


    
    


#