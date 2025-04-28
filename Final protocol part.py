from scapy.all import *

def protocols(pkt):

    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(DHCP):
        return "DHCP"
    if pkt.haslayer(NTP):
        return "NTP"
    if pkt.haslayer(SNMP):
        return "SNMP"
    
    if pkt.haslayer(TCP):
        dport = pkt[TCP].dport

        match dport:
            case 23:
                return "Telnet"
            case 25:
                return "SMTP"
            case 80:
                return "HTTP"
            case 110:
                return "POP3"
            case 119:
                return "NNTP"
            case 143:
                return "IMAP"
            case 194:
                return "IRC"
            case 445:
                return "SMB"
            case 443:
                return "TLS"
            case 20 | 21:
                return "FTP"
            case 22:
                return "SSH"
            case 179:
                return "BGP"
            case _:
                return "TCP"

    if pkt.haslayer(UDP):
        dport = pkt[UDP].dport
        match dport:
            case 123:
                return "NTP"
            case 443:
                return "QUIC"
            case 137:
                return "NBNS"
            case 5353:
                return "MDNS"
            case 1900:
                return "SSDP"
            case 80:
                return "HTTP"
            case 21:
                return "FTP"
            case 22:
                return "SSH"
            case 179:
                return "BGP"
            case 161:
                return "SNMP"
            case _:
                return "UDP"

    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(IP) and pkt[IP].proto == 2:
        return "IGMP"

    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(Ether):
        return hex(pkt[Ether].type)

    return "other"

def packet_sniffer(pkt):
    print(protocols(pkt))

sniff(prn=packet_sniffer)
