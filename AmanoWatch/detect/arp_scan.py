from capture.classes.PyPacket import PyPacket
import time

class _SourceState:
    def __init__(self, ip):
        self.ip = ip
        self.entries = [] # List of dicts {packet: PyPacket, timestamp}
        
    def add(self, packet: PyPacket):
        self.entries.append({
            "packet": packet,
            "timestamp": packet.timestamp
        })
        
    def clean(self, interval):
        cutoff = time.time() - interval
        self.entries = [entry for entry in self.entries if entry["timestamp"] >= cutoff]
        
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
        
    def process_packet(self, packet: PyPacket):
        if not packet.src_ip:
            return
        
        if packet.src_ip not in self.activity:
            self.activity[packet.src_ip] = _SourceState(packet.src_ip)
        state: _SourceState = self.activity[packet.src_ip]
        
        state.add(packet)
        state.clean(self.interval)