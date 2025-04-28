from scapy.all import *

def get_packet_info(packet):
    info = []
    
    if packet.haslayer(ARP):
        arp = packet[ARP]
        if arp.op == 1:
            info.append(f"Who has {arp.pdst}? Tell {arp.psrc}")
        elif arp.op == 2:
            info.append(f"{arp.psrc} is at {arp.hwsrc}")
    
    elif packet.haslayer(ICMP):
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        info.append(f"ICMP Type:{icmp_type} Code:{icmp_code}")
    
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flags = []
        if tcp.flags & 0x01: flags.append("FIN")
        if tcp.flags & 0x02: flags.append("SYN")
        if tcp.flags & 0x04: flags.append("RST")
        if tcp.flags & 0x08: flags.append("PSH")
        if tcp.flags & 0x10: flags.append("ACK")
        if tcp.flags & 0x20: flags.append("URG")
        if tcp.flags & 0x40: flags.append("ECE")
        if tcp.flags & 0x80: flags.append("CWR")
        
        flags_str = ", ".join(flags) if flags else "None"
        info.append(f"{tcp.sport} → {tcp.dport} [{flags_str}]")
    
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        info.append(f"{udp.sport} → {udp.dport}")
    
    if packet.haslayer(DNS):
        dns = packet[DNS]
        if dns.qr == 0:
            name = dns.qd.qname.decode() if dns.qd else ""
            info.append(f"DNS Query: {name}")
        elif dns.qr == 1:
            info.append("DNS Response")

    if packet.haslayer(Raw):
        try:
            load = packet[Raw].load.decode(errors='ignore')
            if "HTTP" in load:
                http_line = load.split('\r\n')[0]
                info.append(f"HTTP: {http_line}")
        except:
            pass
    
    return " | ".join(info) if info else "Unknown packet type"