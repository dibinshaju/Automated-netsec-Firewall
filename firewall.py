#!/usr/bin/env python3
"""
Stage 2+3: Main Firewall Engine
Run with: sudo python3 firewall.py
"""
 
import subprocess
import threading
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP
 
from rules import RuleEngine
from logger import FirewallLogger, ThreatDetector
 
 
class Firewall:
    def __init__(self, interface=None, dry_run=False):
        self.interface = interface
        self.dry_run   = dry_run
        self.running   = False
 
        self.rule_engine = RuleEngine()
        self.logger      = FirewallLogger()
        self.detector    = ThreatDetector(self.logger)
        self.stats       = {"allowed": 0, "blocked": 0, "threats": 0}
 
        print("=" * 60)
        print("PERSONAL FIREWALL ENGINE")
        print("=" * 60)
        print(f"Interface : {interface or 'ALL'}")
        print(f"Dry Run   : {dry_run}")
        print(f"Rules     : {len(self.rule_engine.rules)}")
        print("=" * 60)
 
    def extract_packet_info(self, packet) -> dict | None:
        if IP not in packet:
            return None
 
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"
            src_port = None
            dst_port = None
        else:
            protocol = "OTHER"
            src_port = None
            dst_port = None
 
        src_ip    = packet[IP].src
        dst_ip    = packet[IP].dst
        direction = "outbound" if src_ip.startswith("192.168") else "inbound"
 
        return {
            "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": src_port, "dst_port": dst_port,
            "protocol": protocol, "direction": direction,
            "size": len(packet)
        }
 
    def block_ip_iptables(self, ip: str):
        if self.dry_run:
            print(f"[DRY RUN] Would block IP: {ip}")
            return
        try:
            check = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True
            )
            if check.returncode == 0:
                return
            subprocess.run(
                ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
                check=True
            )
            print(f"iptables: Blocked {ip}")
        except subprocess.CalledProcessError as e:
            print(f"iptables error: {e}")
 
    def unblock_ip_iptables(self, ip: str):
        if self.dry_run:
            print(f"[DRY RUN] Would unblock IP: {ip}")
            return
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True
            )
            print(f"iptables: Unblocked {ip}")
        except subprocess.CalledProcessError:
            print(f"Could not unblock {ip} (may not be blocked)")
 
    def packet_handler(self, packet):
        packet_info = self.extract_packet_info(packet)
        if not packet_info:
            return
 
        src_ip = packet_info["src_ip"]
 
        if self.detector.is_blocked_ip(src_ip):
            self.stats["blocked"] += 1
            self.block_ip_iptables(src_ip)
            return
 
        action, matched_rule = self.rule_engine.evaluate(packet_info)
        rule_desc = matched_rule.description if matched_rule else "Default policy"
        self.logger.log_packet(packet_info, action, rule_desc)
 
        if action == "BLOCK":
            self.stats["blocked"] += 1
            if not self.dry_run:
                self.block_ip_iptables(src_ip)
        else:
            self.stats["allowed"] += 1
 
        threats = self.detector.analyze(packet_info)
        if threats:
            self.stats["threats"] += 1
            self.block_ip_iptables(src_ip)
 
    def print_stats_periodically(self, interval=30):
        while self.running:
            time.sleep(interval)
            if self.running:
                print(
                    f"Stats | Allowed: {self.stats['allowed']} | "
                    f"Blocked: {self.stats['blocked']} | "
                    f"Threats: {self.stats['threats']}"
                )
 
    def start(self):
        self.running = True
        stats_thread = threading.Thread(
            target=self.print_stats_periodically, daemon=True
        )
        stats_thread.start()
        print("\nFirewall started. Press Ctrl+C to stop.\n")
        try:
            sniff(iface=self.interface, prn=self.packet_handler, store=False)
        except KeyboardInterrupt:
            print("\nFirewall stopped by user.")
        finally:
            self.running = False
            self.shutdown()
 
    def shutdown(self):
        print("\n" + "=" * 60)
        print("FINAL STATISTICS")
        print("=" * 60)
        print(f"Packets Allowed : {self.stats['allowed']}")
        print(f"Packets Blocked : {self.stats['blocked']}")
        print(f"Threats Found   : {self.stats['threats']}")
        print("=" * 60)
        self.detector.get_threat_summary()
        self.logger.save_json_log()
        print("Logs saved.")
 
 
def interactive_mode():
    import subprocess
    engine = RuleEngine()
 
    while True:
        print("\nFIREWALL RULE MANAGER")
        print("1. List rules")
        print("2. Add rule")
        print("3. Remove rule")
        print("4. Block IP now")
        print("5. Start firewall")
        print("6. Exit")
 
        choice = input("\nChoice: ").strip()
 
        if choice == "1":
            engine.list_rules()
        elif choice == "2":
            action    = input("Action (ALLOW/BLOCK): ").upper()
            direction = input("Direction (inbound/outbound/any): ").lower()
            protocol  = input("Protocol (TCP/UDP/ICMP or enter for any): ").upper() or None
            src_ip    = input("Source IP (enter for any): ") or None
            dst_ip    = input("Dest IP (enter for any): ") or None
            src_port  = input("Source port (enter for any): ")
            dst_port  = input("Dest port (enter for any): ")
            desc      = input("Description: ")
            engine.add_rule(
                action=action, direction=direction, protocol=protocol,
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=int(src_port) if src_port else None,
                dst_port=int(dst_port) if dst_port else None,
                description=desc
            )
        elif choice == "3":
            rule_id = int(input("Rule ID to remove: "))
            engine.remove_rule(rule_id)
        elif choice == "4":
            ip = input("IP to block: ")
            subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"])
            print(f"Blocked {ip}")
        elif choice == "5":
            interface = input("Interface (enter for all): ") or None
            dry_run   = input("Dry run? (y/n): ").lower() == "y"
            fw = Firewall(interface=interface, dry_run=dry_run)
            fw.start()
            break
        elif choice == "6":
            break
 
 
if __name__ == "__main__":
    import argparse
    import subprocess
 
    parser = argparse.ArgumentParser(description="Personal Firewall")
    parser.add_argument("-i", "--interface",   default=None)
    parser.add_argument("-d", "--dry-run",     action="store_true")
    parser.add_argument("--interactive",       action="store_true")
    args = parser.parse_args()
 
    if args.interactive:
        interactive_mode()
    else:
        fw = Firewall(interface=args.interface, dry_run=args.dry_run)
        fw.start()
