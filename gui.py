 #!/usr/bin/env python3
 
import sys
import threading
from datetime import datetime
 
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QTableWidget, QTableWidgetItem, QPushButton,
    QLabel, QLineEdit, QComboBox, QTabWidget, QHeaderView,
    QMessageBox, QFrame, QSpinBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt5.QtGui import QColor, QFont
 
from rules import RuleEngine
from logger import FirewallLogger, ThreatDetector
 
 
BG_PRIMARY   = "#000000"
BG_SECONDARY = "#111111"
BG_PANEL     = "#1a1a1a"
BG_ROW_ALT   = "#0d0d0d"
 
FG_PRIMARY   = "#ffffff"
FG_SECONDARY = "#bbbbbb"
FG_DIM       = "#666666"
 
BORDER       = "#333333"
BORDER_LIGHT = "#444444"
 
ACTION_ALLOW = "#ffffff"
ACTION_BLOCK = "#555555"
HEADER_BG    = "#1f1f1f"
 
FONT_FAMILY  = "Arial, Sans-Serif, Monospace"
FONT_SIZE    = 11
 
GLOBAL_STYLE = f"""
    * {{
        font-family: Arial, 'Sans-Serif', 'Monospace';
        font-size: {FONT_SIZE}px;
    }}
    QMainWindow, QWidget {{
        background-color: {BG_PRIMARY};
        color: {FG_PRIMARY};
    }}
    QTabWidget::pane {{
        border: 1px solid {BORDER};
        background: {BG_PRIMARY};
    }}
    QTabBar::tab {{
        background: {BG_SECONDARY};
        color: {FG_SECONDARY};
        padding: 8px 24px;
        border: 1px solid {BORDER};
        font-family: Arial, Sans-Serif, Monospace;
        font-size: {FONT_SIZE}px;
    }}
    QTabBar::tab:selected {{
        background: {BG_PANEL};
        color: {FG_PRIMARY};
        border-bottom: 2px solid {FG_PRIMARY};
    }}
    QTableWidget {{
        background: {BG_SECONDARY};
        gridline-color: {BORDER};
        border: 1px solid {BORDER};
        color: {FG_PRIMARY};
        font-family: Arial, Sans-Serif, Monospace;
    }}
    QTableWidget::item {{
        padding: 5px 8px;
    }}
    QTableWidget::item:selected {{
        background: {BG_PANEL};
        color: {FG_PRIMARY};
    }}
    QHeaderView::section {{
        background: {HEADER_BG};
        color: {FG_SECONDARY};
        padding: 6px 8px;
        border: 1px solid {BORDER};
        font-family: Arial, Sans-Serif, Monospace;
        font-size: {FONT_SIZE}px;
        font-weight: bold;
    }}
    QPushButton {{
        background: {BG_PANEL};
        color: {FG_PRIMARY};
        border: 1px solid {BORDER_LIGHT};
        border-radius: 2px;
        padding: 6px 16px;
        font-family: Arial, Sans-Serif, Monospace;
        font-size: {FONT_SIZE}px;
    }}
    QPushButton:hover {{
        background: #2a2a2a;
        border-color: {FG_SECONDARY};
    }}
    QPushButton:pressed {{
        background: #333333;
    }}
    QPushButton#block_btn {{
        border: 1px solid #666666;
        color: #aaaaaa;
    }}
    QPushButton#allow_btn {{
        border: 1px solid {FG_PRIMARY};
        color: {FG_PRIMARY};
    }}
    QLineEdit, QSpinBox {{
        background: {BG_SECONDARY};
        color: {FG_PRIMARY};
        border: 1px solid {BORDER_LIGHT};
        border-radius: 2px;
        padding: 5px 8px;
        font-family: Arial, Sans-Serif, Monospace;
        font-size: {FONT_SIZE}px;
    }}
    QLineEdit:focus, QSpinBox:focus {{
        border-color: {FG_PRIMARY};
    }}
    QComboBox {{
        background: {BG_SECONDARY};
        color: {FG_PRIMARY};
        border: 1px solid {BORDER_LIGHT};
        border-radius: 2px;
        padding: 5px 8px;
        font-family: Arial, Sans-Serif, Monospace;
        font-size: {FONT_SIZE}px;
    }}
    QComboBox QAbstractItemView {{
        background: {BG_PANEL};
        color: {FG_PRIMARY};
        border: 1px solid {BORDER_LIGHT};
        selection-background-color: #2a2a2a;
    }}
    QScrollBar:vertical {{
        background: {BG_SECONDARY};
        width: 10px;
        border: none;
    }}
    QScrollBar::handle:vertical {{
        background: {BORDER_LIGHT};
        min-height: 20px;
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0;
    }}
"""
 
 
class Signals(QObject):
    new_packet   = pyqtSignal(dict)
    new_threat   = pyqtSignal(str, str)
    stats_update = pyqtSignal(dict)
 
 
class StatCard(QFrame):
    def __init__(self, title, value="0"):
        super().__init__()
        self.setFrameShape(QFrame.Box)
        self.setStyleSheet(f"""
            QFrame {{
                background: {BG_SECONDARY};
                border: 1px solid {BORDER_LIGHT};
                border-radius: 2px;
                padding: 12px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
 
        self.value_label = QLabel(value)
        self.value_label.setFont(QFont("Arial", 26, QFont.Bold))
        self.value_label.setStyleSheet(f"color: {FG_PRIMARY}; border: none;")
        self.value_label.setAlignment(Qt.AlignCenter)
 
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet(
            f"color: {FG_DIM}; font-size: 10px; border: none; "
            f"font-family: Arial, Sans-Serif, Monospace;"
        )
        self.title_label.setAlignment(Qt.AlignCenter)
 
        layout.addWidget(self.value_label)
        layout.addWidget(self.title_label)
 
    def set_value(self, value):
        self.value_label.setText(str(value))
 
 
class SectionLabel(QLabel):
    def __init__(self, text):
        super().__init__(text)
        self.setStyleSheet(
            f"color: {FG_SECONDARY}; font-size: 10px; "
            f"font-family: Arial, Sans-Serif, Monospace; "
            f"padding: 6px 0px 2px 0px; border: none; "
            f"letter-spacing: 1px;"
        )
 
 
class FirewallGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Personal Firewall")
        self.setMinimumSize(1100, 760)
        self.setStyleSheet(GLOBAL_STYLE)
 
        self.rule_engine     = RuleEngine()
        self.logger          = FirewallLogger(log_file="firewall.log", json_log="firewall_events.json")
        self.detector        = ThreatDetector(self.logger)
        self.signals         = Signals()
        self.stats           = {"allowed": 0, "blocked": 0, "threats": 0, "total": 0}
        self.sniffing_active = False
 
        self.signals.new_packet.connect(self.on_new_packet)
        self.signals.new_threat.connect(self.on_new_threat)
 
        self._build_ui()
 
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_stats)
        self.timer.start(2000)
 
        self.start_sniffing()
 
    def start_sniffing(self):
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP
        except ImportError:
            print("[WARNING] Scapy not found. Real sniffing unavailable.")
            self._update_sniff_status("Scapy not installed — simulation mode only")
            return
 
        def packet_handler(packet):
            if IP not in packet:
                return
 
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
 
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            direction = "outbound" if src_ip.startswith("192.168") else "inbound"
 
            pkt_info = {
                "src_ip":    src_ip,
                "dst_ip":    dst_ip,
                "src_port":  src_port,
                "dst_port":  dst_port,
                "protocol":  protocol,
                "direction": direction,
                "size":      len(packet),
            }
 
            action, matched_rule = self.rule_engine.evaluate(pkt_info)
            pkt_info["action"] = action
            pkt_info["rule"]   = matched_rule.description if matched_rule else "Default policy"
            pkt_info["time"]   = datetime.now().strftime("%H:%M:%S")
 
            self.logger.log_packet(pkt_info, action, pkt_info["rule"])
 
            self.stats["total"] += 1
            if action == "ALLOW":
                self.stats["allowed"] += 1
            else:
                self.stats["blocked"] += 1
 
            threats = self.detector.analyze(pkt_info)
            if threats:
                self.stats["threats"] += 1
                self.signals.new_threat.emit(threats[0], src_ip)
 
            self.signals.new_packet.emit(pkt_info)
 
        def sniff_loop():
            try:
                self.sniffing_active = True
                self._update_sniff_status("●LIVE — capturing real packets")
                sniff(prn=packet_handler, store=False)
            except PermissionError:
                self._update_sniff_status("⚠ Permission denied — run with sudo for live capture")
                print("[ERROR] Permission denied. Run: sudo python3 gui.py")
            except Exception as e:
                self._update_sniff_status(f"⚠ Sniff error: {e}")
                print(f"[ERROR] Sniffing stopped: {e}")
            finally:
                self.sniffing_active = False
 
        threading.Thread(target=sniff_loop, daemon=True).start()
 
    def _update_sniff_status(self, message: str):
        QTimer.singleShot(0, lambda: self.sniff_status_label.setText(message))
 
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(20, 20, 20, 20)
 
        header_row = QHBoxLayout()
        title = QLabel("PERSONAL FIREWALL")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setStyleSheet(f"color: {FG_PRIMARY}; letter-spacing: 2px;")
        subtitle = QLabel("Network Monitor and Filter")
        subtitle.setStyleSheet(f"color: {FG_DIM}; font-size: 10px; font-family: Arial;")
        subtitle.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        header_row.addWidget(title)
        header_row.addStretch()
        header_row.addWidget(subtitle)
        main_layout.addLayout(header_row)
 
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet(f"color: {BORDER};")
        main_layout.addWidget(line)
 
        cards_row = QHBoxLayout()
        cards_row.setSpacing(10)
        self.card_total   = StatCard("TOTAL PACKETS")
        self.card_allowed = StatCard("ALLOWED")
        self.card_blocked = StatCard("BLOCKED")
        self.card_threats = StatCard("THREATS")
        for card in [self.card_total, self.card_allowed, self.card_blocked, self.card_threats]:
            cards_row.addWidget(card)
        main_layout.addLayout(cards_row)
 
        tabs = QTabWidget()
        tabs.addTab(self._build_traffic_tab(), "LIVE TRAFFIC")
        tabs.addTab(self._build_rules_tab(),   "RULES")
        tabs.addTab(self._build_threats_tab(), "THREATS")
        tabs.addTab(self._build_block_tab(),   "QUICK BLOCK")
        main_layout.addWidget(tabs)
 
    def _build_traffic_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(8)
 
        self.sniff_status_label = QLabel(" Starting live capture...")
        self.sniff_status_label.setStyleSheet(
            f"color: {FG_SECONDARY}; font-size: 10px; padding: 2px 0px;"
        )
        layout.addWidget(self.sniff_status_label)
 
        ctrl = QHBoxLayout()
        self.sim_btn = QPushButton("Simulate Traffic")
        self.sim_btn.setObjectName("allow_btn")
        self.sim_btn.clicked.connect(self.simulate_traffic)
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(lambda: self.traffic_table.setRowCount(0))
        ctrl.addWidget(self.sim_btn)
        ctrl.addWidget(self.clear_btn)
        ctrl.addStretch()
        layout.addLayout(ctrl)
 
        self.traffic_table = QTableWidget(0, 7)
        self.traffic_table.setHorizontalHeaderLabels([
            "TIME", "ACTION", "PROTOCOL", "SOURCE", "DESTINATION", "PORT", "RULE"
        ])
        self.traffic_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.traffic_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.traffic_table.verticalHeader().setVisible(False)
        self.traffic_table.setAlternatingRowColors(False)
        layout.addWidget(self.traffic_table)
        return w
 
    def _build_rules_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(8)
 
        layout.addWidget(SectionLabel("ACTIVE RULES"))
        self.rules_table = QTableWidget(0, 8)
        self.rules_table.setHorizontalHeaderLabels([
            "ID", "ACTION", "DIRECTION", "PROTOCOL",
            "SRC IP", "DST IP", "DST PORT", "DESCRIPTION"
        ])
        self.rules_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.rules_table.verticalHeader().setVisible(False)
        self.rules_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.rules_table)
        self.refresh_rules_table()
 
        layout.addWidget(SectionLabel("ADD NEW RULE"))
        form = QHBoxLayout()
        form.setSpacing(6)
 
        self.r_action    = QComboBox(); self.r_action.addItems(["BLOCK", "ALLOW"])
        self.r_direction = QComboBox(); self.r_direction.addItems(["inbound", "outbound", "any"])
        self.r_protocol  = QComboBox(); self.r_protocol.addItems(["ANY", "TCP", "UDP", "ICMP"])
        self.r_dst_ip    = QLineEdit(); self.r_dst_ip.setPlaceholderText("Dst IP")
        self.r_dst_port  = QSpinBox();  self.r_dst_port.setRange(0, 65535)
        self.r_desc      = QLineEdit(); self.r_desc.setPlaceholderText("Description")
 
        add_btn = QPushButton("Add Rule")
        add_btn.setObjectName("allow_btn")
        add_btn.clicked.connect(self.add_rule)
 
        del_btn = QPushButton("Delete Selected")
        del_btn.setObjectName("block_btn")
        del_btn.clicked.connect(self.delete_rule)
 
        for widget in [self.r_action, self.r_direction, self.r_protocol,
                       self.r_dst_ip, self.r_dst_port, self.r_desc, add_btn, del_btn]:
            form.addWidget(widget)
        layout.addLayout(form)
        return w
 
    def _build_threats_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.addWidget(SectionLabel("DETECTED THREATS"))
 
        self.threats_table = QTableWidget(0, 4)
        self.threats_table.setHorizontalHeaderLabels(["TIME", "THREAT TYPE", "SOURCE IP", "DETAILS"])
        self.threats_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.threats_table.verticalHeader().setVisible(False)
        self.threats_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.threats_table)
        return w
 
    def _build_block_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setAlignment(Qt.AlignTop)
        layout.setSpacing(10)
 
        layout.addWidget(SectionLabel("QUICK IP BLOCK / UNBLOCK"))
 
        row = QHBoxLayout()
        self.block_ip_input = QLineEdit()
        self.block_ip_input.setPlaceholderText("Enter IP address  e.g.  192.168.1.100")
        block_btn   = QPushButton("Block IP");   block_btn.setObjectName("block_btn")
        unblock_btn = QPushButton("Unblock IP"); unblock_btn.setObjectName("allow_btn")
        block_btn.clicked.connect(self.quick_block)
        unblock_btn.clicked.connect(self.quick_unblock)
        row.addWidget(self.block_ip_input)
        row.addWidget(block_btn)
        row.addWidget(unblock_btn)
        layout.addLayout(row)
 
        self.block_status = QLabel("")
        self.block_status.setStyleSheet(f"color: {FG_SECONDARY}; padding: 6px 0px;")
        layout.addWidget(self.block_status)
        return w
 
    def on_new_packet(self, data: dict):
        row    = self.traffic_table.rowCount()
        self.traffic_table.insertRow(row)
        action = data.get("action", "?")
 
        bg = QColor(BG_SECONDARY) if row % 2 == 0 else QColor(BG_ROW_ALT)
 
        cells = [
            data.get("time", ""),
            action,
            data.get("protocol", "?"),
            data.get("src_ip", "?"),
            data.get("dst_ip", "?"),
            str(data.get("dst_port", "?")),
            data.get("rule", "")
        ]
        for col, val in enumerate(cells):
            item = QTableWidgetItem(val)
            item.setBackground(bg)
            if col == 1:
                fg = QColor(ACTION_ALLOW) if action == "ALLOW" else QColor(ACTION_BLOCK)
                item.setForeground(fg)
                item.setFont(QFont("Arial", FONT_SIZE, QFont.Bold))
            else:
                item.setForeground(QColor(FG_PRIMARY if action == "ALLOW" else FG_SECONDARY))
            self.traffic_table.setItem(row, col, item)
 
        self.traffic_table.scrollToBottom()
        if self.traffic_table.rowCount() > 200:
            self.traffic_table.removeRow(0)
 
    def on_new_threat(self, threat_type: str, src_ip: str):
        row = self.threats_table.rowCount()
        self.threats_table.insertRow(row)
        cells = [datetime.now().strftime("%H:%M:%S"), threat_type, src_ip, "Auto-flagged"]
        for col, val in enumerate(cells):
            item = QTableWidgetItem(val)
            item.setForeground(QColor(FG_SECONDARY))
            item.setBackground(QColor(BG_PANEL))
            self.threats_table.setItem(row, col, item)
 
    def refresh_stats(self):
        self.card_total.set_value(self.stats["total"])
        self.card_allowed.set_value(self.stats["allowed"])
        self.card_blocked.set_value(self.stats["blocked"])
        self.card_threats.set_value(self.stats["threats"])
 
    def refresh_rules_table(self):
        self.rules_table.setRowCount(0)
        for rule in self.rule_engine.rules:
            row = self.rules_table.rowCount()
            self.rules_table.insertRow(row)
            bg = QColor(BG_SECONDARY) if row % 2 == 0 else QColor(BG_ROW_ALT)
            cells = [
                str(rule.id), rule.action, rule.direction,
                rule.protocol or "ANY", rule.src_ip or "ANY",
                rule.dst_ip or "ANY", str(rule.dst_port or "ANY"),
                rule.description
            ]
            for col, val in enumerate(cells):
                item = QTableWidgetItem(val)
                item.setBackground(bg)
                if col == 1:
                    fg = QColor(FG_PRIMARY) if rule.action == "ALLOW" else QColor(FG_DIM)
                    item.setForeground(fg)
                    item.setFont(QFont("Arial", FONT_SIZE, QFont.Bold))
                else:
                    item.setForeground(QColor(FG_PRIMARY))
                self.rules_table.setItem(row, col, item)
 
    def add_rule(self):
        protocol = self.r_protocol.currentText()
        self.rule_engine.add_rule(
            action=self.r_action.currentText(),
            direction=self.r_direction.currentText(),
            protocol=None if protocol == "ANY" else protocol,
            dst_ip=self.r_dst_ip.text() or None,
            dst_port=self.r_dst_port.value() or None,
            description=self.r_desc.text()
        )
        self.refresh_rules_table()
 
    def delete_rule(self):
        selected = self.rules_table.currentRow()
        if selected < 0:
            QMessageBox.warning(self, "Warning", "Select a rule first.")
            return
        rule_id = int(self.rules_table.item(selected, 0).text())
        self.rule_engine.remove_rule(rule_id)
        self.refresh_rules_table()
 
    def quick_block(self):
        ip = self.block_ip_input.text().strip()
        if not ip:
            return
        self.rule_engine.add_rule(
            action="BLOCK", direction="any",
            src_ip=ip, description=f"Quick block {ip}"
        )
        self.block_status.setText(f"Blocked: {ip}")
        self.refresh_rules_table()
 
    def quick_unblock(self):
        ip = self.block_ip_input.text().strip()
        if not ip:
            return
        for rule in self.rule_engine.rules[:]:
            if rule.src_ip == ip and rule.action == "BLOCK":
                self.rule_engine.remove_rule(rule.id)
        self.block_status.setText(f"Unblocked: {ip}")
        self.refresh_rules_table()
 
    def simulate_traffic(self):
        import random, time
 
        sample_packets = [
            {"direction": "outbound", "protocol": "TCP",  "src_ip": "192.168.1.10",
             "dst_ip": "142.250.80.46",  "src_port": 54321, "dst_port": 443},
            {"direction": "outbound", "protocol": "UDP",  "src_ip": "192.168.1.10",
             "dst_ip": "8.8.8.8",        "src_port": 12345, "dst_port": 53},
            {"direction": "inbound",  "protocol": "TCP",  "src_ip": "45.33.32.156",
             "dst_ip": "192.168.1.10",   "src_port": 9000,  "dst_port": 22},
            {"direction": "inbound",  "protocol": "TCP",  "src_ip": "10.0.0.99",
             "dst_ip": "192.168.1.10",   "src_port": 6666,  "dst_port": 23},
            {"direction": "outbound", "protocol": "TCP",  "src_ip": "192.168.1.10",
             "dst_ip": "93.184.216.34",  "src_port": 55001, "dst_port": 80},
        ]
 
        def run():
            for _ in range(25):
                pkt           = random.choice(sample_packets).copy()
                action, rule  = self.rule_engine.evaluate(pkt)
                pkt["action"] = action
                pkt["rule"]   = rule.description if rule else "Default"
                pkt["time"]   = datetime.now().strftime("%H:%M:%S")
 
                self.stats["total"] += 1
                if action == "ALLOW":
                    self.stats["allowed"] += 1
                else:
                    self.stats["blocked"] += 1
 
                threats = self.detector.analyze(pkt)
                if threats:
                    self.stats["threats"] += 1
                    self.signals.new_threat.emit(threats[0], pkt["src_ip"])
 
                self.signals.new_packet.emit(pkt)
                time.sleep(0.12)
 
        threading.Thread(target=run, daemon=True).start()
 
 
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = FirewallGUI()
    window.show()
    sys.exit(app.exec_())
 
