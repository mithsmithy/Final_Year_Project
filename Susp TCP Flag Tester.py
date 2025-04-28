from scapy.all import *

# source to, set with an easy to recognize IP
target = "99.99.99.99"

send(IP(dst=target)/TCP(flags="SF"))   # SYN+FIN
send(IP(dst=target)/TCP(flags="SR"))   # SYN+RST
send(IP(dst=target)/TCP(flags="FR"))   # FIN+RST
send(IP(dst=target)/TCP(flags="FSR"))  # XMAS 
send(IP(dst=target)/TCP(flags=0))      # NULL
send(IP(dst=target)/TCP(flags="P"))    # PSH only