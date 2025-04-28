from scapy.all import sniff, Ether, IP
from mac_vendor_lookup import MacLookup

mac = MacLookup()
mac.update_vendors()

def route(pkt):

    if pkt.haslayer(IP):
            srcIP = pkt[IP].src
            dstIP = pkt[IP].dst

    elif pkt.haslayer(Ether):
        try:
            srcIP = mac.lookup(pkt[Ether].src)
        except:
            srcIP = pkt[Ether].src

        try:
            if pkt[Ether].dst == "ff:ff:ff:ff:ff:ff":
                dstIP = "Broadcast"
            else:
                dstIP = mac.lookup(pkt[Ether].dst)
        except:
            dstIP = pkt[Ether].dst
    else:
        srcIP, dstIP = "none"
    
    return srcIP, dstIP

def test(pkt):
    x,y = route(pkt)
    print(y)
    print(x)

sniff(prn=test)