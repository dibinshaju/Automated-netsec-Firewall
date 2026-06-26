#!/usr/bin/env python3
"""
Stage 2: Rule Engine
Defines and evaluates firewall rules
"""
 
import json
import os
from dataclasses import dataclass
from typing import Optional
 
 
@dataclass
class Rule:
    id: int
    action: str
    direction: str
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    description: str = ""
 
    def matches(self, packet_info: dict) -> bool:
        if self.direction != "any":
            if self.direction != packet_info.get("direction"):
                return False
        if self.protocol:
            if self.protocol.upper() != packet_info.get("protocol", "").upper():
                return False
        if self.src_ip:
            if self.src_ip != packet_info.get("src_ip"):
                return False
        if self.dst_ip:
            if self.dst_ip != packet_info.get("dst_ip"):
                return False
        if self.src_port:
            if self.src_port != packet_info.get("src_port"):
                return False
        if self.dst_port:
            if self.dst_port != packet_info.get("dst_port"):
                return False
        return True
 
 
class RuleEngine:
    DEFAULT_RULES_FILE = "rules.json"
 
    def __init__(self, rules_file: str = DEFAULT_RULES_FILE):
        self.rules_file = rules_file
        self.rules: list[Rule] = []
        self.default_action = "ALLOW"
        self._next_id = 1
        self._load_rules()
 
    def _load_rules(self):
        if not os.path.exists(self.rules_file):
            self._create_default_rules()
            return
        try:
            with open(self.rules_file, "r") as f:
                data = json.load(f)
                self.default_action = data.get("default_action", "ALLOW")
                for r in data.get("rules", []):
                    rule = Rule(**r)
                    self.rules.append(rule)
                    self._next_id = max(self._next_id, rule.id + 1)
            print(f"Loaded {len(self.rules)} rules from {self.rules_file}")
        except Exception as e:
            print(f"Error loading rules: {e}. Using defaults.")
            self._create_default_rules()
 
    def _create_default_rules(self):
        self.rules = [
            Rule(id=1, action="ALLOW", direction="outbound", protocol="TCP", dst_port=80,   description="Allow HTTP outbound"),
            Rule(id=2, action="ALLOW", direction="outbound", protocol="TCP", dst_port=443,  description="Allow HTTPS outbound"),
            Rule(id=3, action="ALLOW", direction="outbound", protocol="UDP", dst_port=53,   description="Allow DNS outbound"),
            Rule(id=4, action="ALLOW", direction="inbound",  protocol="TCP", dst_port=22,   description="Allow SSH inbound"),
            Rule(id=5, action="BLOCK", direction="inbound",  protocol="TCP", dst_port=23,   description="Block Telnet inbound"),
            Rule(id=6, action="BLOCK", direction="inbound",  protocol="TCP", dst_port=3389, description="Block RDP inbound"),
        ]
        self._next_id = 7
        self.save_rules()
        print(f"Created {len(self.rules)} default rules")
 
    def save_rules(self):
        data = {
            "default_action": self.default_action,
            "rules": [vars(r) for r in self.rules]
        }
        with open(self.rules_file, "w") as f:
            json.dump(data, f, indent=2)
 
    def evaluate(self, packet_info: dict) -> tuple[str, Optional[Rule]]:
        for rule in self.rules:
            if rule.matches(packet_info):
                return rule.action, rule
        return self.default_action, None
 
    def add_rule(self, action, direction, protocol=None,
                 src_ip=None, dst_ip=None,
                 src_port=None, dst_port=None,
                 description="", position=None):
        rule = Rule(
            id=self._next_id,
            action=action.upper(),
            direction=direction.lower(),
            protocol=protocol.upper() if protocol else None,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            description=description
        )
        self._next_id += 1
        if position is not None:
            self.rules.insert(position, rule)
        else:
            self.rules.append(rule)
        self.save_rules()
        print(f"Rule #{rule.id} added: {action} {direction} {protocol or 'ANY'}")
        return rule
 
    def remove_rule(self, rule_id: int) -> bool:
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                removed = self.rules.pop(i)
                self.save_rules()
                print(f"Rule #{rule_id} removed: {removed.description}")
                return True
        print(f"Rule #{rule_id} not found")
        return False
 
    def list_rules(self):
        print("\n" + "=" * 90)
        print(f"{'ID':<5} {'ACTION':<8} {'DIR':<10} {'PROTO':<7} "
              f"{'SRC IP':<16} {'DST IP':<16} {'S.PORT':<8} {'D.PORT':<8} DESCRIPTION")
        print("=" * 90)
        for r in self.rules:
            print(
                f"{r.id:<5} {r.action:<8} {r.direction:<10} "
                f"{r.protocol or 'ANY':<7} "
                f"{r.src_ip or 'ANY':<16} {r.dst_ip or 'ANY':<16} "
                f"{str(r.src_port or 'ANY'):<8} {str(r.dst_port or 'ANY'):<8} "
                f"{r.description}"
            )
        print("=" * 90)
        print(f"Default policy : {self.default_action}")
        print(f"Total rules    : {len(self.rules)}\n")
 
 
if __name__ == "__main__":
    engine = RuleEngine()
    engine.list_rules()
 
    test_packets = [
        {"direction": "outbound", "protocol": "TCP", "src_ip": "192.168.1.10",
         "dst_ip": "8.8.8.8", "src_port": 54321, "dst_port": 443},
        {"direction": "inbound",  "protocol": "TCP", "src_ip": "10.0.0.5",
         "dst_ip": "192.168.1.10", "src_port": 54321, "dst_port": 23},
    ]
 
    print("PACKET EVALUATION TEST")
    print("-" * 60)
    for pkt in test_packets:
        action, rule = engine.evaluate(pkt)
        rule_desc = rule.description if rule else "Default policy"
        print(f"{action} | {pkt['src_ip']}:{pkt['src_port']} -> "
              f"{pkt['dst_ip']}:{pkt['dst_port']} | Rule: {rule_desc}")
 
