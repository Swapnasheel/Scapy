'''
Usage: 
    - For help -> python send_traffic -h (or) python send_traffic --help
    - sudo python send_traffic.py -if 'eth0' -dip 10.0.2.15 -p "Hello" -c 3

Author:
Swapnasheel Sonkamble
'''


import argparse, random
import os, socket
from scapy.all import *

class Interface():
    def __init__(self, iface=''):
        self.iface = iface

    def get_iface(self):
        try:
            interface = [i for i in get_if_list() if self.iface in i]
        except:
            print "Cannot find interface"
        return interface[0]

    def add_vlan_tag(self, tag):
        vlan_tag = Dot1Q(vlan=int(tag))
        return vlan_tag


# Using the argparse, create a parser for the arguments
def create_parser():
    parser = argparse.ArgumentParser(description = "Get arguments for parser")

    parser.add_argument('-if', '--iface', metavar='', help="Needs an interface as an argument", required=True)
    parser.add_argument('-dip','--dest_ip', metavar='', help="Needs a destination IP as an argument", required=True)
    parser.add_argument('-p', '--msg', metavar='', help="Payload!", required=True)
    parser.add_argument('-vlan', '--vlan', metavar='', help="If you need to add a VLAN tag", type=int)
    parser.add_argument('-c', '--count', metavar='', help="Number of packets to send", type=int)

    return parser

def Main():

    args = create_parser().parse_args()
    addr = socket.gethostbyname(args.dest_ip)  

    p = Interface(args.iface)
    iface = p.get_iface()
    
    if args.vlan:
        vlan_tag = p.add_vlan_tag(args.vlan)
        pkt = Ether(src=get_if_hwaddr(iface), dst = "ff:ff:ff:ff:ff:ff")/ vlan_tag
    else:
        pkt = Ether(src=get_if_hwaddr(iface), dst = "ff:ff:ff:ff:ff:ff")
    
    pkt = pkt / IP(dst=addr)/ TCP(dport=12345, sport=random.randint(50000, 65000))/ args.msg

    for c in range(0, args.count):  
        sendp(pkt, iface=iface, verbose=False) 

if __name__ == '__main__':
    Main()
