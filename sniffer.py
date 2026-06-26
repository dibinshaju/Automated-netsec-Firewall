#!/usr/bin/env python3
"""
Stage 1: Packet Sniffer
Captures and displays all incoming/outgoing network traffic
Run with: sudo python3 sniffer.py
"""
 
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
 
 
class PacketSniffer:
    def __init__(self, packet_limit=0, interface=None):
        """
        packet_limit: 0 = sniff forever, N = stop after N packets
        interface: None = all interfaces, or specify e.g. 'eth0', 'wlan0'
        """
        self.packet_limit = packet_limit
        self.interface = interface
        self.packet_count = 0
        self.stats = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "OTHER": 0
        }
 
    def get_protocol(self, packet):
        """Identify packet protocol"""
        if TCP in packet:
            return "TCP"
        elif UDP in packet:
            return "UDP"
        elif ICMP in packet:
            return "ICMP"
        else:
            return "OTHER"
 
    def get_port_info(self, packet):
        """Extract source and destination ports"""
        if TCP in packet:
            return packet[TCP].sport, packet[TCP].dport
        elif UDP in packet:
            return packet[UDP].sport, packet[UDP].dport
        return None, None
 
    def get_flags(self, packet):
        """Get TCP flags if present"""
        if TCP in packet:
            flags = packet[TCP].flags
            flag_str = []
            if flags & 0x01: flag_str.append("FIN")
            if flags & 0x02: flag_str.append("SYN")
            if flags & 0x04: flag_str.append("RST")
            if flags & 0x08: flag_str.append("PSH")
            if flags & 0x10: flag_str.append("ACK")
            if flags & 0x20: flag_str.append("URG")
            return "|".join(flag_str) if flag_str else "NONE"
        return "-"
 
    def packet_callback(self, packet):
        """Called for every captured packet"""
        if IP not in packet:
            return  # Skip non-IP packets
 
        self.packet_count += 1
        protocol = self.get_protocol(packet)
        self.stats[protocol] += 1
 
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port, dst_port = self.get_port_info(packet)
        flags = self.get_flags(packet)
        size = len(packet)
        timestamp = datetime.now().strftime("%H:%M:%S")
 
        # Format port display
        port_info = ""
        if src_port and dst_port:
            port_info = f"{src_port} → {dst_port}"
 
        # Color coding by protocol
        colors = {
            "TCP":   "\033[94m",   # Blue
            "UDP":   "\033[92m",   # Green
            "ICMP":  "\033[93m",   # Yellow
            "OTHER": "\033[97m"    # White
        }
        reset = "\033[0m"
        color = colors.get(protocol, reset)
 
        print(
            f"{color}[{timestamp}] #{self.packet_count:04d} "
            f"{protocol:<5} | "
            f"{src_ip:<15} → {dst_ip:<15} | "
            f"Ports: {port_info:<20} | "
            f"Flags: {flags:<15} | "
            f"Size: {size}B{reset}"
        )
 
    def print_stats(self):
        """Print summary statistics"""
        print("\n" + "="*60)
        print("📊 CAPTURE STATISTICS")
        print("="*60)
        print(f"Total Packets : {self.packet_count}")
        for proto, count in self.stats.items():
            pct = (count / self.packet_count * 100) if self.packet_count > 0 else 0
            bar = "█" * int(pct / 5)
            print(f"{proto:<6} : {count:>5} ({pct:>5.1f}%) {bar}")
        print("="*60)
 
    def start(self):
        """Start sniffing"""
        print("="*60)
        print("🔥 PERSONAL FIREWALL - PACKET SNIFFER")
        print("="*60)
        print(f"Interface : {self.interface or 'ALL'}")
        print(f"Limit     : {self.packet_limit or 'Unlimited'}")
        print("Press Ctrl+C to stop\n")
 
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                count=self.packet_limit,
                store=False  # Don't store in memory
            )
        except KeyboardInterrupt:
            print("\n⛔ Sniffing stopped by user")
        finally:
            self.print_stats()
 
 
if __name__ == "__main__":
    import argparse
 
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface (e.g. eth0)", default=None)
    parser.add_argument("-c", "--count", help="Number of packets to capture (0=unlimited)", type=int, default=0)
    args = parser.parse_args()
 
    sniffer = PacketSniffer(
        packet_limit=args.count,
        interface=args.interface
    )
    sniffer.start()
#!/usr/bin/env python3
"""
Stage 1: Packet Sniffer
Captures and displays all incoming/outgoing network traffic
Run with: sudo python3 sniffer.py
"""
 
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
 
 
class PacketSniffer:
    def __init__(self, packet_limit=0, interface=None):
        self.packet_limit = packet_limit
        self.interface = interface
        self.packet_count = 0
        self.stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
 
    def get_protocol(self, packet):
        if TCP in packet:
            return "TCP"
        elif UDP in packet:
            return "UDP"
        elif ICMP in packet:
            return "ICMP"
        return "OTHER"
 
    def get_port_info(self, packet):
        if TCP in packet:
            return packet[TCP].sport, packet[TCP].dport
        elif UDP in packet:
            return packet[UDP].sport, packet[UDP].dport
        return None, None
 
    def get_flags(self, packet):
        if TCP in packet:
            flags = packet[TCP].flags
            flag_str = []
            if flags & 0x01: flag_str.append("FIN")
            if flags & 0x02: flag_str.append("SYN")
            if flags & 0x04: flag_str.append("RST")
            if flags & 0x08: flag_str.append("PSH")
            if flags & 0x10: flag_str.append("ACK")
            if flags & 0x20: flag_str.append("URG")
            return "|".join(flag_str) if flag_str else "NONE"
        return "-"
 
    def packet_callback(self, packet):
        if IP not in packet:
            return
 
        self.packet_count += 1
        protocol = self.get_protocol(packet)
        self.stats[protocol] += 1
 
        src_ip     = packet[IP].src
        dst_ip     = packet[IP].dst
        src_port, dst_port = self.get_port_info(packet)
        flags      = self.get_flags(packet)
        size       = len(packet)
        timestamp  = datetime.now().strftime("%H:%M:%S")
 
        port_info = ""
        if src_port and dst_port:
            port_info = f"{src_port} -> {dst_port}"
 
        print(
            f"[{timestamp}] #{self.packet_count:04d} "
            f"{protocol:<5} | "
            f"{src_ip:<15} -> {dst_ip:<15} | "
            f"Ports: {port_info:<20} | "
            f"Flags: {flags:<15} | "
            f"Size: {size}B"
        )
 
    def print_stats(self):
        print("\n" + "=" * 60)
        print("CAPTURE STATISTICS")
        print("=" * 60)
        print(f"Total Packets : {self.packet_count}")
        for proto, count in self.stats.items():
            pct = (count / self.packet_count * 100) if self.packet_count > 0 else 0
            bar = "#" * int(pct / 5)
            print(f"{proto:<6} : {count:>5} ({pct:>5.1f}%) {bar}")
        print("=" * 60)
 
    def start(self):
        print("=" * 60)
        print("PERSONAL FIREWALL - PACKET SNIFFER")
        print("=" * 60)
        print(f"Interface : {self.interface or 'ALL'}")
        print(f"Limit     : {self.packet_limit or 'Unlimited'}")
        print("Press Ctrl+C to stop\n")
 
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                count=self.packet_limit,
                store=False
            )
        except KeyboardInterrupt:
            print("\nSniffing stopped by user.")
        finally:
            self.print_stats()
 
 
if __name__ == "__main__":
    import argparse
 
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-i", "--interface", default=None)
    parser.add_argument("-c", "--count", type=int, default=0)
    args = parser.parse_args()
 
    sniffer = PacketSniffer(packet_limit=args.count, interface=args.interface)
    sniffer.start()
