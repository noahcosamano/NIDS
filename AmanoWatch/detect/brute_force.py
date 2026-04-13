import time
from capture.classes.PyPacket import PyPacket
from detect.config import BRUTE_PORTS
from database.edit import add_detection
from queue import Queue
from threading import Event

class _SourceState:
    def __init__(self, ip):
        self.ip = ip
        self.entries = []        # {packet, dst_ip, dst_port, timestamp}
        self.targeted_services = set()  # (dst_ip, dst_port) pairs

    def add(self, packet: PyPacket):
        self.entries.append({
            "packet": packet,
            "dst_ip": packet.dst_ip,
            "dst_port": packet.dst_port,
            "timestamp": packet.timestamp
        })
        self.targeted_services.add((packet.dst_ip, packet.dst_port))

    def clean(self, interval):
        cutoff = time.time() - interval
        self.entries = [e for e in self.entries if e["timestamp"] >= cutoff]
        self.targeted_services = {(e["dst_ip"], e["dst_port"]) for e in self.entries}

    def calculate_risk(self):
        """
        High volume to same service = brute force
        High volume across many services = credential stuffing / spray

        total=30, services=1 → focused brute force → high risk
        total=30, services=10 → spray attack → medium risk
        total=5,  services=1 → low risk
        """
        if not self.entries:
            self.risk = 0.0
            return

        total = len(self.entries)
        services = len(self.targeted_services)
        focus_ratio = 1 / services  # higher = more focused on one target

        self.risk = total * focus_ratio + services * 0.5
        
class BruteForce:
    def __init__(self, interval=60, cooldown=30, alert_callback=None):
        self.interval = interval
        self.cooldown = cooldown
        self.alert_callback = alert_callback
        self.activity = {}
        self.last_alert = {}
        self.last_severity = {}
        
    def process_packet(self, packet: PyPacket):
        if packet.dst_port not in BRUTE_PORTS:
            return
        if not packet.src_ip or packet.protocol != "TCP":
            return
        if not packet.flags == "SYN":
            return
        
        if packet.src_ip not in self.activity:
            self.activity[packet.src_ip] = _SourceState(packet.src_ip)
        state: _SourceState = self.activity[packet.src_ip]
        
        state.add(packet)
        state.clean(self.interval)
        state.calculate_risk()
        
        severity_rank = {"medium": 0, "high": 1, "critical": 2}
        
        if state.risk >= 40.0:
            severity = "critical"
        elif state.risk >= 25.0:
            severity = "high"
        elif state.risk >= 12.0:
            severity = "medium"
        else:
            return
        
        now = time.time()
        last_sev = self.last_severity.get(packet.src_ip)
        since_last = now - self.last_alert.get(packet.src_ip, 0)
        
        # Allow alert if: severity escalated, OR cooldown has expired
        if last_sev is not None:
            escalated = severity_rank[severity] > severity_rank[last_sev]
            if not escalated and since_last < self.cooldown:
                return

        self.last_alert[packet.src_ip] = now
        self.last_severity[packet.src_ip] = severity

        self.detected(severity, packet, state)
        
    def detected(self, severity, packet: PyPacket, state: _SourceState):
        summary = (
            f"{state.ip} sent {len(state.entries)}+ to {len(state.targeted_services)} sign-on services"
            f" in {self.interval}s (Possible brute force attempt)"
        )
        
        details = (
            f"Source: {packet.src_ip}\n"
            f"Number of total connections: {len(state.entries)}\n"
            f"Number of sign-on services targeted: {len(state.targeted_services)}\n"
            f"Risk score: {state.risk:.2f}\n"
            f"Recent connections:\n"
        )
        
        for entry in state.entries[-10:]:
            details += (
                f"  {time.ctime(entry['timestamp'])} | "
                f"Destination IP: {entry["dst_ip"]} | Destination Port: {entry["dst_port"]}\n"
            )
            
        if self.alert_callback:
            self.alert_callback(
                severity,
                "Brute Force",
                summary + "\n" + details
            )
            
        add_detection(
            detector_type="Brute Force",
            severity=severity,
            summary=summary,
            src_ip=packet.src_ip,
            src_mac=packet.src_mac,
            src_port=packet.src_port,
            dst_ip=packet.dst_ip,
            dst_mac=packet.dst_mac,
            dst_port=packet.dst_port,
            details=details,
        )
        
def detect_brute_force(packet_queue: Queue, stop_event: Event, cli_ready: Event, alert_callback=None):
    detector = BruteForce(alert_callback=alert_callback)
    
    while not stop_event.is_set() and cli_ready.is_set():
        packet = packet_queue.get()
        try:
            detector.process_packet(packet)
        finally:
            packet_queue.task_done()