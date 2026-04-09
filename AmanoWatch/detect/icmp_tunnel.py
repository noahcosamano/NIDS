from capture.classes.PyPacket import PyPacket

class _SourceState:
    def __init__(self, packet_count=0, risk=0):
        self.packet_count = packet_count
        self.risk = risk
        
    def _increment(self):
        self.packet_count += 1
        
    def _calculate_risk(self):
        self.risk = ...

class IcmpTunnel:
    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        self.activity = {} # Maps source IP to SourceState, which tracks packet_count and risk
        
    def process_packet(self, packet: PyPacket):
        if not packet.payload or packet.src_ip:
            return
        
        payload_len = len(packet.payload)
        
        if packet.src_ip not in self.activity:
            self.activity[packet.src_ip] = _SourceState()
        packet_state: _SourceState = self.activity[packet.src_ip]
        
        packet_state._increment()
        
        