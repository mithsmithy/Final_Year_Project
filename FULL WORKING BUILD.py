import tkinter as tk
import threading
import time
import socket

from scapy.all import sniff, wrpcap
from mac_vendor_lookup import MacLookup
from tkinter import ttk, messagebox, filedialog

class PacketSniffer:
    # initialization function
    def __init__(self, root):
        self.root = root
        # create a window for the app to run in
        self.root.title("JS Packet Sniffer")
        self.root.geometry("1024x768")

        # set the sniffing state
        self.sniff_active = False
        self.sniff_thread = None

        # initialize vendor lookup and update vendors (comment out update part after you have run it once)
        self.mac_lookup = MacLookup()
        #self.mac_lookup.update_vendors()

        # storage and mapping for packets
        self.all_packets = []             
        self.packet_map = {}

        # sets filter state
        self.current_filter = None

        # treeview configuration
        self.columns = ("Time", "Source", "Destination", "Protocol", "Length", "Info", "Alerts")
        self.sort_state = {"current_col": None, "order": None}

        # Anomaly detection trackers
        self.src_tracker = {} 
                                    
        self.threshold_time = 10
        self.threshold_count = 50

        self.arp_table = {}
        self.abnormal_length_threshold = 5000

        # get device ip so that we can filter out that ip from DOS attack tests                    
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            self.local_ip = sock.getsockname()[0]
            sock.close()
        except Exception:
            self.local_ip = ""
               
        self.setup_ui()

    def setup_ui(self):
        # top row buttons setup
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(fill=tk.X, pady=5)

        self.start_btn = ttk.Button(btn_frame, text="Start", command=self.start)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(btn_frame, text="Stop", command=self.stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)

        self.clear_btn = ttk.Button(btn_frame, text="Clear", command=self.clear_data)
        self.clear_btn.pack(side=tk.RIGHT, padx=(5, 20))

        self.save_btn = ttk.Button(btn_frame, text="Save", command=self.save_to_file)
        self.save_btn.pack(side=tk.RIGHT)

        # filtering section setup
        filter_frame = ttk.Frame(self.root)
        filter_frame.pack(fill=tk.X, padx=5, pady=2)

        ttk.Label(filter_frame, text="Filter Field:").pack(side=tk.LEFT)
        self.filter_field = ttk.Combobox(filter_frame, values=["Time", "Source", "Destination", "Protocol"],state="readonly", width=10)
        self.filter_field.current(0)
        self.filter_field.pack(side=tk.LEFT, padx=5)

        ttk.Label(filter_frame, text="Filter Text:").pack(side=tk.LEFT)
        self.filter_entry = ttk.Entry(filter_frame, width=20)
        self.filter_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Apply Filter", command=self.apply_filter).pack(side=tk.LEFT)
        ttk.Button(filter_frame, text="Clear Filter", command=self.clear_filter).pack(side=tk.LEFT, padx=5)

        # packet display area
        tree_frame = ttk.Frame(self.root)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree = ttk.Treeview(tree_frame, columns=self.columns, show="headings", yscrollcommand=scrollbar.set)
        self.tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.tree.yview)
                                                     
        for col in self.columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_column(c))
            self.tree.column(col, width=100)

        # double click for advanced packet view                                                    
        self.tree.bind("<Double-1>", self.show_packet_details)

    def start(self):
        # start sniffing on a separate thread so it doesn't freeze the UI
        self.sniff_active = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)                                                
        self.sniff_thread = threading.Thread(target=self.sniff_loop, daemon=True)
        self.sniff_thread.start()
        print("Sniffer started.")

    def sniff_loop(self):
        # continuously loop to capture packets
        while self.sniff_active:                                 
            sniff(timeout=1, prn=self.process_packet, store=False)

    def stop(self):
        # stop packet capture
        self.sniff_active = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        print("Sniffer stopped.")

    def process_packet(self, packet):
        # processing of each packet
        current_time = time.time()               
        timestamp = time.strftime('%H:%M:%S')
        src, dst = self.extract_ips(packet)                                                   
        info = self.extract_info(packet)                               
        length = len(packet)                                                   
        protocol = self.identify_protocol(packet)
        alerts = self.detect_anomalies(packet, src, length, current_time)
        alerts_str = ", ".join(alerts) if alerts else ""
        data = (timestamp, src, dst, protocol, length, info, alerts_str)
        self.root.after(0, self.add_row, data, packet)
        self.all_packets.append((data, packet))

    def detect_anomalies(self, packet, src, pkt_length, current_time):
        # analyse packets to alert on suspicious ones
        alerts = []                                             
        if src and src != "none" and src != self.local_ip:
            last_time, count = self.src_tracker.get(src, (current_time, 0))                                                                                                   
            count = count + 1 if current_time - last_time < self.threshold_time else 1
        
            self.src_tracker[src] = (current_time, count)
            if count > self.threshold_count:
                alerts.append("High Freq Src")

        # ARP spoofing detection
        if packet.haslayer("ARP"):
            arp_layer = packet["ARP"]
            ip_src = arp_layer.psrc
            mac_src = arp_layer.hwsrc.upper()
            if ip_src in self.arp_table and self.arp_table[ip_src] != mac_src:
                alerts.append("ARP Spoofing")
            else:
                self.arp_table[ip_src] = mac_src

        # unusual packet length detection
        if pkt_length > self.abnormal_length_threshold:
            alerts.append("Unusual Length")

        # suspicious TCP flags detection
        if packet.haslayer("TCP"):
            tcp_layer = packet["TCP"]
            flags = tcp_layer.flags

            if (flags & 0x01 and flags & 0x02 and flags & 0x04): # FIN + SYN + RST (XMAS)
                alerts.append("Suspicious TCP: XMAS")
            elif (flags & 0x02 and flags & 0x04): # SYN + RST
                alerts.append("Suspicious TCP: SYN+RST")
            elif (flags & 0x01 and flags & 0x04): # FIN + RST
                alerts.append("Suspicious TCP: FIN+RST")
            elif (flags & 0x02 and flags & 0x01): # SYN + FIN
                alerts.append("Suspicious TCP: SYN+FIN")
            elif flags == 0x00: # NULL
                alerts.append("Suspicious TCP: NULL")
            elif flags == 0x08: # PSH only
                alerts.append("Suspicious TCP: PSH Only")

        return alerts

    def identify_protocol(self, pkt):
        # identify the correct protocol of each packet
        if pkt.haslayer("DNS"):
            if pkt.haslayer("UDP") and pkt["UDP"].dport == 5353:
                return "MDNS"
                 
            return "DNS"
        if pkt.haslayer("DHCP"):
            return "DHCP"
        if pkt.haslayer("NTP"):
            return "NTP"
        if pkt.haslayer("SNMP"):
            return "SNMP"
        
        if pkt.haslayer("TCP"):
            dport = pkt["TCP"].dport
            port_map = {23: "Telnet", 25: "SMTP", 80: "HTTP", 110: "POP3",
                        119: "NNTP", 143: "IMAP", 194: "IRC", 445: "SMB",
                        443: "TLS", 20: "FTP", 21: "FTP", 22: "SSH", 179: "BGP"}
            return port_map.get(dport, "TCP")
           
        if pkt.haslayer("UDP"):
            dport = pkt["UDP"].dport
            port_map = {123: "NTP", 443: "QUIC", 137: "NBNS", 5353: "MDNS",
                        1900: "SSDP", 80: "HTTP", 21: "FTP", 22: "SSH",
                        179: "BGP", 161: "SNMP", 3702: "UDP/XML"}
            return port_map.get(dport, "UDP")
           
        if pkt.haslayer("ICMP"):
            return "ICMP"
        if pkt.haslayer("IP") and pkt["IP"].proto == 2:
            return "IGMP"
        if pkt.haslayer("ARP"):
            return "ARP"
        if pkt.haslayer("IPv6"):
            return "ICMPv6"
        if pkt.haslayer("Ether"):
            return hex(pkt["Ether"].type).upper()
        return "other"

    def extract_ips(self, pkt):
        # extract source and destination addresses or vendor names
        if pkt.haslayer("IP"):
            return pkt["IP"].src, pkt["IP"].dst
                                
        if pkt.haslayer("IPv6"):
            return pkt["IPv6"].src.upper(), pkt["IPv6"].dst.upper()
                                            
        if pkt.haslayer("Ether"):
            try:
                src = self.mac_lookup.lookup(pkt["Ether"].src)
            except Exception:
                src = pkt["Ether"].src.upper()
            try:
                dst = self.mac_lookup.lookup(pkt["Ether"].dst) if pkt["Ether"].dst != "ff:ff:ff:ff:ff:ff" else "Broadcast"                                                   
            except Exception:
                dst = pkt["Ether"].dst.upper()
             
            return src, dst
        return "none", "none"

    def extract_info(self, pkt):
        # get brief info on each packet
        info_parts = []

        if pkt.haslayer("ARP"):
            arp = pkt["ARP"]
            if arp.op == 1:
                info_parts.append(f"Who has {arp.pdst}? Tell {arp.psrc}")
            elif arp.op == 2:
                info_parts.append(f"{arp.psrc} is at {arp.hwsrc.upper()}")
               
        if pkt.haslayer("TCP"):
            tcp = pkt["TCP"]
            flags = []
            if tcp.flags & 0x01: flags.append("FIN")
            if tcp.flags & 0x02: flags.append("SYN")
            if tcp.flags & 0x04: flags.append("RST")
            if tcp.flags & 0x08: flags.append("PSH")
            if tcp.flags & 0x10: flags.append("ACK")
            if tcp.flags & 0x20: flags.append("URG")
            if tcp.flags & 0x40: flags.append("ECE")
            if tcp.flags & 0x80: flags.append("CWR")
                                                             
            info_parts.append(f"{tcp.sport} → {tcp.dport} [{', '.join(flags) or 'None'}]")
           
        elif pkt.haslayer("UDP"):
            udp = pkt["UDP"]
            info_parts.append(f"{udp.sport} → {udp.dport}")
                     
        if pkt.haslayer("DNS"):
            dns = pkt["DNS"]
            if dns.qr == 0 and dns.qd is not None:
                try:
                    name = dns.qd.qname.decode()
                except Exception:
                    name = ""
                info_parts.append(f"DNS Query: {name}")
            elif dns.qr == 1:
                info_parts.append("DNS Response")

        if pkt.haslayer("IPv6"):
            type_map = {
                128: "Echo Request", 129: "Echo Reply", 133: "Router Solicitation",
                134: "Router Advertisement", 135: "Neighbor Solicitation",
                136: "Neighbor Advertisement", 143: "Multicast Listener Report"}

            try:
                layer_type = pkt[2].type
                if layer_type in type_map:
                    info_parts.append(type_map[layer_type])
            except Exception:
                pass
                                       
        if pkt.haslayer("Raw"):
            try:
                load = pkt["Raw"].load.decode(errors='ignore')
                if "HTTP" in load:
                    http_line = load.split('\r\n')[0]
                    info_parts.append(f"HTTP: {http_line}")
            except Exception:
                pass

        return " | ".join(info_parts) if info_parts else "No Info"

    def add_row(self, data, packet):
        # add new packets if they pass the filter                                                  
        if self.current_filter:
            field, filter_text = self.current_filter
            field_index = self.columns.index(field)
            if filter_text not in str(data[field_index]).lower():
                return
        
        row_id = self.tree.insert('', 'end', values=data)
        self.packet_map[row_id] = packet
        self.tree.yview_moveto(1)

    def sort_column(self, col):
        # packet sorting functionality                                                  
        if self.sort_state["current_col"] and self.sort_state["current_col"] != col:
            self.tree.heading(self.sort_state["current_col"], text=self.sort_state["current_col"])
            self.sort_state["order"] = None
                
        if self.sort_state["current_col"] == col:
            if self.sort_state["order"] == 'asc':
                self.sort_state["order"] = 'desc'
            elif self.sort_state["order"] == 'desc':
                self.sort_state["order"] = None
            else:
                self.sort_state["order"] = 'asc'
        else:
            self.sort_state["order"] = 'asc'

        self.sort_state["current_col"] = col
                     
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.packet_map.clear()
                                 
        if self.sort_state["order"] is None:
            self.tree.heading(col, text=col)
                                        
            packets_show = self.all_packets if not self.current_filter else [
                (data, pkt) for (data, pkt) in self.all_packets
                if self.current_filter[1] in str(data[self.columns.index(self.current_filter[0])]).lower()
            ]
            sorted_packets = sorted(packets_show, key=lambda x: x[0][self.columns.index("Time")])
        else:
               
            field_index = self.columns.index(col)
            reverse = self.sort_state["order"] == 'desc'
            packets_show = self.all_packets if not self.current_filter else [
                (data, pkt) for (data, pkt) in self.all_packets
                if self.current_filter[1] in str(data[self.columns.index(self.current_filter[0])]).lower()
            ]
            sorted_packets = sorted(packets_show, key=lambda x: x[0][field_index], reverse=reverse)

            arrow = "▲" if self.sort_state["order"] == 'asc' else "▼"
            self.tree.heading(col, text=f"{col} {arrow}")

        for data, packet in sorted_packets:
            row_id = self.tree.insert('', 'end', values=data)
            self.packet_map[row_id] = packet

    def apply_filter(self):
        # apply filter settings
        field = self.filter_field.get()
        filter_text = self.filter_entry.get().strip().lower()
        self.current_filter = (field, filter_text) if filter_text else None
                   
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.packet_map.clear()
                                                
        field_index = self.columns.index(field)
        for data, packet in self.all_packets:
            if self.current_filter is None or filter_text in str(data[field_index]).lower():
                row_id = self.tree.insert('', 'end', values=data)
                self.packet_map[row_id] = packet

    def clear_filter(self):
        # reset filtering
        self.current_filter = None
        self.filter_entry.delete(0, tk.END)
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.packet_map.clear()

        for data, packet in self.all_packets:
            row_id = self.tree.insert('', 'end', values=data)
            self.packet_map[row_id] = packet
                         
        for col in self.columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_column(c))
        self.sort_state = {"current_col": None, "order": None}

    def show_packet_details(self, event):
        # display detailed packet details in a separate window
        selected_row = self.tree.focus()
        packet = self.packet_map.get(selected_row)
        if not packet:
            return

        detail_window = tk.Toplevel(self.root)
        detail_window.title("Packet Details")
        detail_window.geometry("600x500")
                  
        text_widget = tk.Text(detail_window, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True)
        text_widget.tag_config("bold", font=("Courier", 12, "bold"))

        raw_details = packet.show(dump=True)
        for line in raw_details.splitlines():
            line = line.strip()
            if "= []" in line:
                continue
            if "###[" in line and "]###" in line:
                header_text = line.strip(" #[]|")
                text_widget.insert(tk.END, "\n" + header_text + "\n", "bold")
            else:
                text_widget.insert(tk.END, line + "\n")

    def save_to_file(self):
        # save captured packets as a PCAP file
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP Files", "*.pcap")], title="Save Packet Capture")
         
        if not file_path:
            return

        try:                                                                   
            packets = [pkt for data, pkt in self.all_packets]
            wrpcap(file_path, packets)
            messagebox.showinfo("Saved", f"Saved to:\n{file_path}")
        except Exception as ex:
            messagebox.showerror("Error", f"Could not save file: {ex}")

    def clear_data(self):
        # clear all packets in the frame and filters and sorts
        if self.all_packets:
            confirm = messagebox.askyesno("Clear Data", "Clear all captured packets?")
            if not confirm:
                return
                                       
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.packet_map.clear()
        self.all_packets.clear()
        self.current_filter = None
                                 
        self.src_tracker.clear()
        self.arp_table.clear()
              
        if self.sort_state["current_col"]:
            self.tree.heading(self.sort_state["current_col"], text=self.sort_state["current_col"])
                                    
        self.sort_state = {"current_col": None, "order": None}


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSniffer(root)
    root.mainloop()