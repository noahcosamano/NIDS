from capture.classes import PyPacket
from log.log import report_to_webhook
import math
from collections import Counter 
import time

WHITELIST = {
    "azure.com", 
    "microsoft.com", 
    "windowsupdate.com", 
    "amazonaws.com", 
    "google.com", 
    "akamai.net",
    "sharepoint.com"
}

class DnsTunnel:
    def __init__(self, packet_queue, alert_callback=None):
        self.packet_queue = packet_queue
        self.alert_callback = alert_callback
    
    def process_packet(self, packet: PyPacket):
        domain_name = self.parse_dns_name(packet.query)
        
        if not domain_name or domain_name.endswith(".local"):
            return
        
        if any(domain_name.endswith(trusted) for trusted in WHITELIST):
            return
        
        entropy = self.string_entropy(domain_name)
        
        if entropy > 4.0:
            message = (
                f"\n{time.ctime()}\nDNS Tunnel Detected\n"
                f"Source IP: {packet.src_ip}\n"
                f"Domain: {domain_name}\n"
                f"Entropy: {entropy:.2f}\n"
                f"Blocking {packet.src_ip} for 300 seconds\n"
            )
            report_to_webhook("DNS Tunnel", message)
            if self.alert_callback:
                self.alert_callback("warning", "DNS TUNNELING", f"High-entropy domain from {packet.src_ip}: \
                                    {domain_name} (entropy={entropy:.2f})")
            
        
    def string_entropy(self, payload):
        if not payload:
            return 0.0
            
        freq = Counter(payload).values()
        total = len(payload)
        
        entropy = 0.0
        for count in freq:
            p_x = count / total
            # math.log2(0) is the "Domain Error". 
            # Since p_x is always > 0 here (because count comes from Counter),
            # this is just a safety habit.
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return entropy
    
    def parse_dns_name(self, payload: bytes) -> str:
        """Extracts the domain name from the Question section of a DNS packet."""
        try:
            if len(payload) < 13: return ""
            # DNS Name starts at offset 12
            data = payload[12:]
            parts = []
            i = 0
            while i < len(data):
                length = data[i]
                if length == 0: break
                if length > 63: return "" # DNS labels max out at 63
                i += 1
                parts.append(data[i:i+length].decode('utf-8', errors='ignore'))
                i += length
            return ".".join(parts)
        except Exception:
            return ""
    
def detect_dns_tunnel(packet_queue, stop_event, cli_ready, alert_callback=None):
    detector = DnsTunnel(packet_queue, alert_callback=alert_callback)
    
    while not stop_event.is_set() and cli_ready.is_set():
        packet = packet_queue.get()
        try:
            detector.process_packet(packet)
        finally:
            packet_queue.task_done()
        
        
        
        