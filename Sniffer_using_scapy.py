from scapy.all import *
import logging
import subprocess


class Sniff():

    packet_no = 0

    def __init__(self):
	self.get_interface_details()
	self.get_sniff_details()
	self.sniff()

    def packet_log(pkt):

    	#Creating an external file for packet logging
	self.file_name = raw_input("* Please give a name to the log file: ")
        self.sniffer_log = open(file_name, "w")

        if self.protocol.lower() in pkt[0][1].summary().lower():
            packet_no = packet_no + 1
            #Writing the data for each packet to the external file
            print >>sniffer_log, "Packet " + str(packet_no) + ": " + "SMAC: " + pkt[0].src + " DMAC: " + pkt[0].dst

    def get_interface_details(self):
    	self.net_int = raw_input("[+] Enter the interface you wish to sniff: (Eg. eth0): -> ")
    	subprocess.call(['ifconfig', self.net_int, 'promisc'], stdout=None, stderr=None, shell=False)

    	print "[INFO] Setting interface %s in promisc mode.." %self.net_int

    def get_sniff_details(self):
    	self.pkt_to_sniff = raw_input("[+] Enter the number of packets to sniff (0 is infinity): -> ")
    	if int(self.pkt_to_sniff) != 0:
    		print "[INFO] The program will capture %s number of packets." %self.pkt_to_sniff
    	else:
    		print "[INFO] The program will capture packets until keyboard interupts"

    	self.time_to_sniff = raw_input("[+] Enter the number of seconds to run the capture: -> ")
    	if int(self.time_to_sniff) != 0:
    		print "[INFO] The program will capture for %s number of seconds " %self.time_to_sniff
    	else:
    		print "[ERROR] Please enter a valid time!"

    	self.protocol = raw_input("[+] Specify any protocol you wish to filter (arp | icmp | 0 is all) : -> ")


    def sniff(self):
	print "[+] Sniffing starting for %s seconds.... " %self.time_to_sniff
	self.pkt = sniff(iface=self.net_int, count=int(self.pkt_to_sniff), timeout=int(self.time_to_sniff)).show() #prn=self.packet_log)
        
#        self.pkt.show()
        #Printing the closing message
        print "[INFO] The timeout of %s seconds has passed." %self.time_to_sniff
#        print "[INFO] Please check the %s file to see the captured packets.\n" %self.file_name
 
#        self.sniffer_log.close()


# Set logging parameters/ thresholds
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)


print "\n Make sure the program run's in root..\n"

s = Sniff()


