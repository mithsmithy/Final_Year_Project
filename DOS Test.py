from scapy.all import *
# rapidly send ICMP packets
send(IP(src="99.99.99.99", dst="99.99.99.99")/ICMP(), count=100, inter=0.01)