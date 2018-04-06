'''
Usage:
    - sudo python receive.py -p 12345

Author:
Swapnasheel
'''

import os, sys, argparse
from scapy.all import *


def create_parser():

    parser = argparse.ArgumentParser(description="To allow user to pass inputs")
    parser.add_argument('-p', '--port', help="Port to sniff on", type=int, required=True)
#    parser.add_argument('-i', '--iface', help="Interface to sniff on")
    
    return parser


def handle_pkt(pkt, port):
    # Filter for TCP 
    if TCP in pkt and pkt[TCP].dport==port:
        print "Got a packet!"
        pkt.show2()
        sys.stdout.flush()


def Main():
    # Get interface eth0 from the /sys/class/net/ directory
    args = create_parser().parse_args()
    iface = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))[0]
    print "Sniffing on %s " % iface
    sys.stdout.flush()
    sniff(iface=iface, prn=lambda x: handle_pkt(x, args.port))


if __name__ == '__main__':
    Main()
