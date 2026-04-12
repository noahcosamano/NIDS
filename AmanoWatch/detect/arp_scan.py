from capture.classes.PyPacket import PyPacket
from database.edit import add_detection
from queue import Queue
from threading import Event
import time

class _SourceState:
    def __init__(self, ip):
        self.ip = ip
        self.entries = [] # List of dicts {packet: PyPacket, dst_ip, timestamp}
        self.unique_ips = set()
        self.risk = 0
        
    def add(self, packet: PyPacket):
        self.entries.append({
            "packet": packet,
            "dst_ip": packet.dst_ip,
            "timestamp": packet.timestamp
        })
        
        self.unique_ips.add(packet.dst_ip)
        
    def clean(self, interval):
        cutoff = time.time() - interval
        self.entries = [entry for entry in self.entries if entry["timestamp"] >= cutoff]
        self.unique_ips = {entry["dst_ip"] for entry in self.entries}
        
    def calculate_risk(self):
        """
        Calculates risk based on number of ARP requests sent to unique IP's 
        within the given time window.
        
        total = 4, unique = 4
            ratio = 1
            risk = 4 * 2 + 4 * 1 = 12
        total = 4, unique = 2
            ratio = 0.5
            risk = 2 * 2 + 4 * 0.5 = 6
        total = 20, unique = 2
            ratio = 0.1
            risk = 2 * 2 + 20 * 0.1 = 6
        """
        if not self.entries:
            self.risk = 0.0
            return
        
        total = len(self.entries)
        unique = len(self.unique_ips)
        unique_ratio = unique / total if total > 0 else 0
        self.risk = unique * 2 + total * unique_ratio
        
    @property
    def packet_count(self):
        return len(self.entries)
    
class ArpScan:
    def __init__(self, interval=60, cooldown=30, alert_callback=None):
        self.interval = interval
        self.cooldown = cooldown
        self.alert_callback = alert_callback
        self.activity = {} # src_ip -> _SourceState
        self.last_alert = {} # src_ip -> timestamp
        self.last_severity = {}
        
    def process_packet(self, packet: PyPacket):
        if not packet.src_ip or not packet.dst_ip:
            return
        
        if packet.src_ip not in self.activity:
            self.activity[packet.src_ip] = _SourceState(packet.src_ip)
        state: _SourceState = self.activity[packet.src_ip]
        
        state.add(packet)
        state.clean(self.interval)
        state.calculate_risk()
        
        severity_rank = {"medium": 0, "high": 1, "critical": 2}
        
        if state.risk >= 10.0:
            severity = "critical"
        elif state.risk >= 7.5:
            severity = "high"
        elif state.risk >= 5.0:
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
        
    def detected(self, severity: str, packet: PyPacket, state: _SourceState):
        summary = (
            f"{packet.src_ip} sent {len(state.unique_ips)}+ unique ARP requests"
            f" in {self.interval} seconds (possible ARP scan)"
        )

        details = (
            f"Source: {packet.src_ip}\n"
            f"Number of total requests: {len(state.entries)}\n"
            f"Number of unique requests: {len(state.unique_ips)}\n"
            f"Risk score: {state.risk:.2f}\n"
            f"Recent requests:\n"
        )
        for entry in state.entries[-10:]:
            details += (
                f"  {time.ctime(entry['timestamp'])} | "
                f"Destination IP: {entry["dst_ip"]}\n"
            )

        if self.alert_callback:
            self.alert_callback(
                severity,
                "ARP Scanning",
                f"{state.ip} sent {len(state.unique_ips)}+ unique ARP requests sent in {self.interval}s"
            )

        add_detection(
            detector_type="ARP Scan",
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
        
def detect_arp_scan(packet_queue: Queue, stop_event: Event, cli_ready: Event, alert_callback=None):
    detector = ArpScan(alert_callback=alert_callback)
    
    while not stop_event.is_set() and cli_ready.is_set():
        packet = packet_queue.get()
        try:
            detector.process_packet(packet)
        finally:
            packet_queue.task_done()