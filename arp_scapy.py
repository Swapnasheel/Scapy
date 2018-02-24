### This is a simple demonstration of how you can
### check connected host IP and MAC addresses using Scapy


# import library

from scapy.all import *


default_router = '192.168.0.*'

def arpp():
    p = arping(default_router)


arpp()
