#!/usr/bin/env python3
"""
Stage 3: Logger and Threat Detector
"""
 
import logging
import json
from datetime import datetime
from collections import defaultdict
 
 
class FirewallLogger:
    def __init__(self, log_file="firewall.log", json_log="firewall_events.json"):
        self.log_file  = log_file
        self.json_log  = json_log
        self.events    = []
 
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s | %(levelname)s | %(message)s",
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("Firewall")
 
    def log_packet(self, packet_info: dict, action: str, rule_desc: str = "Default"):
        event = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "rule": rule_desc,
            **packet_info
        }
        self.events.append(event)
        level = logging.INFO if action == "ALLOW" else logging.WARNING
        self.logger.log(
            level,
            f"{action:<6} | "
            f"{packet_info.get('protocol','?'):<5} | "
            f"{packet_info.get('src_ip','?')}:{packet_info.get('src_port','?')} -> "
            f"{packet_info.get('dst_ip','?')}:{packet_info.get('dst_port','?')} | "
            f"Rule: {rule_desc}"
        )
        if len(self.events) % 50 == 0:
            self.save_json_log()
 
    def log_threat(self, threat_type: str, src_ip: str, details: str):
        self.logger.critical(
            f"THREAT DETECTED | {threat_type} | Source: {src_ip} | {details}"
        )
 
    def save_json_log(self):
        with open(self.json_log, "w") as f:
            json.dump(self.events, f, indent=2)
 
    def get_stats(self) -> dict:
        total   = len(self.events)
        blocked = sum(1 for e in self.events if e["action"] == "BLOCK")
        allowed = total - blocked
        return {
            "total":      total,
            "allowed":    allowed,
            "blocked":    blocked,
            "block_rate": f"{(blocked/total*100):.1f}%" if total > 0 else "0%"
        }
 
 
class ThreatDetector:
    def __init__(self, logger: FirewallLogger):
        self.logger              = logger
        self.port_scan_tracker   = defaultdict(set)
        self.connection_rate     = defaultdict(list)
        self.blocked_ips         = set()
 
        self.PORT_SCAN_THRESHOLD  = 10
        self.RATE_LIMIT_THRESHOLD = 50
        self.TIME_WINDOW          = 60
 
    def analyze(self, packet_info: dict) -> list[str]:
        threats  = []
        src_ip   = packet_info.get("src_ip")
        dst_port = packet_info.get("dst_port")
        now      = datetime.now().timestamp()
 
        if not src_ip:
            return threats
 
        # Port scan detection
        if dst_port:
            self.port_scan_tracker[src_ip].add(dst_port)
            ports_tried = len(self.port_scan_tracker[src_ip])
            if ports_tried >= self.PORT_SCAN_THRESHOLD:
                if src_ip not in self.blocked_ips:
                    self.blocked_ips.add(src_ip)
                    self.logger.log_threat(
                        "PORT SCAN", src_ip,
                        f"Tried {ports_tried} ports: "
                        f"{sorted(self.port_scan_tracker[src_ip])[:10]}"
                    )
                threats.append("PORT_SCAN")
 
        # Rate limiting
        self.connection_rate[src_ip].append(now)
        self.connection_rate[src_ip] = [
            t for t in self.connection_rate[src_ip]
            if now - t < self.TIME_WINDOW
        ]
        rate = len(self.connection_rate[src_ip])
        if rate >= self.RATE_LIMIT_THRESHOLD:
            if src_ip not in self.blocked_ips:
                self.blocked_ips.add(src_ip)
                self.logger.log_threat(
                    "RATE LIMIT", src_ip,
                    f"{rate} connections in {self.TIME_WINDOW}s"
                )
            threats.append("RATE_LIMIT")
 
        # Dangerous ports
        dangerous_ports = {
            23: "Telnet", 135: "RPC", 137: "NetBIOS",
            445: "SMB", 3389: "RDP", 5900: "VNC"
        }
        if packet_info.get("direction") == "inbound" and dst_port in dangerous_ports:
            self.logger.log_threat(
                "DANGEROUS PORT", src_ip,
                f"Attempt on {dangerous_ports[dst_port]} port {dst_port}"
            )
            threats.append("DANGEROUS_PORT")
 
        return threats
 
    def is_blocked_ip(self, ip: str) -> bool:
        return ip in self.blocked_ips
 
    def reset_ip(self, ip: str):
        self.port_scan_tracker.pop(ip, None)
        self.connection_rate.pop(ip, None)
        self.blocked_ips.discard(ip)
        print(f"Reset tracking for {ip}")
 
    def get_threat_summary(self):
        print("\n" + "=" * 50)
        print("THREAT DETECTION SUMMARY")
        print("=" * 50)
        print(f"Flagged IPs    : {len(self.blocked_ips)}")
        print(f"IPs monitoring : {len(self.port_scan_tracker)}")
        if self.blocked_ips:
            print("\nFlagged IPs:")
            for ip in self.blocked_ips:
                ports = len(self.port_scan_tracker.get(ip, set()))
                print(f"  {ip} | Ports probed: {ports}")
        print("=" * 50)
 
 
if __name__ == "__main__":
    logger   = FirewallLogger()
    detector = ThreatDetector(logger)
 
    print("Testing threat detection...\n")
    attacker_ip = "10.0.0.99"
    print(f"Simulating port scan from {attacker_ip}...")
    for port in range(20, 35):
        pkt = {
            "direction": "inbound", "protocol": "TCP",
            "src_ip": attacker_ip, "dst_ip": "192.168.1.10",
            "src_port": 54321, "dst_port": port
        }
        threats = detector.analyze(pkt)
        if threats:
            print(f"  Threats detected: {threats}")
            break
 
    detector.get_threat_summary()
    print(f"\nLog stats: {logger.get_stats()}")
