from scapy.all import *

def prn(pkt):
    print(pkt.summary())
sniff(prn=prn)