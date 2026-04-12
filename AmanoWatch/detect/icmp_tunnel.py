from capture.classes.PyPacket import PyPacket
from database.edit import add_detection
import time
from queue import Queue
from threading import Event

class _SourceState:
    def __init__(self, ip):
        self.ip = ip
        self.packets = [] # Holds PyPackets
        self.packet_count = 0
        self.risk = 0
        
    def _add_packet(self, packet: PyPacket):
        self.packets.append(packet)
    
    def _update_packet_count(self):
        self.packet_count = len(self.packets)
        
    def _clean_packets(self, interval):
        now = time.time()
        cutoff = now - interval # The windows where packets are still kept and tracked
        
        self.packets = [packet for packet in self.packets if packet.timestamp >= cutoff] # Gets rid of packets not in the cutoff
        
    def _calculate_risk(self):
        '''
        Risk scales linearly with total payload bytes in the window.
            1 byte  → 0.01 risk
            500 bytes → 5.0 (medium threshold)
            1000 bytes → 10.0 (critical threshold)
        A single 1000-byte ping, or 10 × 100-byte pings, both hit critical.
        '''
        total_bytes = sum(len(packet.payload) for packet in self.packets if packet.payload)
        self.risk = total_bytes * 0.01

class IcmpTunnel:
    def __init__(self, interval=60, alert_callback=None):
        self.alert_callback = alert_callback
        self.interval = interval
        self.activity = {} # Maps source IP to SourceState, which tracks packet_count and risk
        
    def process_packet(self, packet: PyPacket):
        print(f"DEBUG: {packet.protocol} Packet received")
        if not packet.payload or not packet.src_ip:
            print(f"DEBUG: IP or payload missing")
            return
        
        if packet.src_ip not in self.activity:
            self.activity[packet.src_ip] = _SourceState(packet.src_ip)
        source_state: _SourceState = self.activity[packet.src_ip]
        
        source_state._add_packet(packet)
        source_state._clean_packets(self.interval)
        source_state._update_packet_count()
        
        source_state._calculate_risk()
        risk = source_state.risk
        print(f"DEBUG: Risk: {risk}")
        
        if (5.0 <= risk < 7.5):
            self.detected("medium", packet, source_state)
        elif (7.5 <= risk < 10):
            self.detected("high", packet, source_state)
        elif (10 <= risk):
            self.detected("critical", packet, source_state)
        
    def detected(self, severity, packet: PyPacket, source_state: _SourceState):
        summary = f"ICMP packet(s) from {source_state.ip} may contain suspicious payload(s)"
        details = f"Calculated risk: {source_state.risk}\nPayloads:\n"
        for pkt in source_state.packets:
            details += f"Time: {pkt.timestamp} | Payload: {pkt.payload}\n"
            
        if self.alert_callback:
            self.alert_callback(
                severity,
                "ICMP TUNNELING",
                f"Suspiscious payload(s) from {source_state.ip} ({source_state.packet_count} packets sent)"
            )
            
        add_detection(
            detector_type="ICMP Tunnel", 
            severity=severity, 
            summary=summary, 
            src_ip=packet.src_ip, 
            src_mac=packet.src_mac, 
            src_port=packet.src_port, dst_ip=
            packet.dst_ip, dst_mac=
            packet.dst_mac, dst_port=
            packet.dst_port, details=
            details
        )
        
def detect_icmp_tunnel(packet_queue: Queue, stop_event: Event, cli_ready: Event, alert_callback=None):
    detector = IcmpTunnel(alert_callback=alert_callback)

    while not stop_event.is_set() and cli_ready.is_set():
        packet = packet_queue.get()
        try:
            detector.process_packet(packet)
        finally:
            packet_queue.task_done()