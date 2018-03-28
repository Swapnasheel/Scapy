
'''

A much nicer code with classes for different IP headers is stored in the
Packet-Sniffer repository.

Kindly visit that if you are looking for socket based python sniffer!

Thank you!


'''

#!/usr/bin/python3.4

import struct
import socket

def main():

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print("Ethernet Frame..")
        print("Destination: {}, Source: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto))


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:] 


def get_mac_addr(mac):
    byte_str = map('{:02x}'.format, mac)
    return ':'.join(byte_str).upper()


if __name__ == '__main__':
    main()


