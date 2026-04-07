from capture.classes.PyPacket import PyPacket
from log.log import report_to_webhook
from detect.config import DNS_WHITELIST
import math
from collections import Counter 
import time

class DnsTunnel:
    def __init__(self, packet_queue, alert_callback=None):
        self.packet_queue = packet_queue
        self.alert_callback = alert_callback
        self.risk = 0.0 # Flag if risk > 5.0
        
    def _subdomain(self, domain: str) -> str:
        parts = domain.rstrip(".").split(".")
        if len(parts) <= 2:
            return ""
        return ".".join(parts[:-2])
    
    def process_packet(self, packet: PyPacket):
        domain = self.parse_dns_name(packet.query)
        subdomain_name = self._subdomain(domain)
        subdomain_len = len(subdomain_name)
        
        if not subdomain_name or domain.endswith(".local"):
            return
        
        if domain.endswith(".arpa"):  # reverse DNS lookups
            return
            
        # Skip if domain contains non-ASCII garbage from bad parsing
        if not all(c.isprintable() and ord(c) < 128 for c in subdomain_name):
            return
        
        if any(domain.endswith(trusted) for trusted in DNS_WHITELIST):
            return
        
        entropy = self.string_entropy(subdomain_name)
        
        self.risk += entropy
        self.risk += (subdomain_len * 0.01)
        
        if (5.0 <= self.risk < 5.5):
            self.detect_tunnel(packet, domain, "MEDIUM")
        elif (5.5 <= self.risk < 6.0):
            self.detect_tunnel(packet, domain, "HIGH")
        elif (6.0 <= self.risk):
            self.detect_tunnel(packet, domain, "CRITICAL")
            
        self.risk = 0
        
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
        
    def detect_tunnel(self, packet, domain_name, severity):
        message = (
                f"\n{time.ctime()}\nDNS Tunnel Detected\n"
                f"Severity: {severity}\n"
                f"Source IP: {packet.src_ip}\n"
                f"Domain: {domain_name}\n"
                f"Blocking {packet.src_ip} for 300 seconds\n"
            )
        report_to_webhook("DNS Tunnel", message)
        if self.alert_callback:
            self.alert_callback(severity, "DNS TUNNELING", f"High-entropy domain from {packet.src_ip}: \
                                {domain_name}")
    
def detect_dns_tunnel(packet_queue, stop_event, cli_ready, alert_callback=None):
    detector = DnsTunnel(packet_queue, alert_callback=alert_callback)
    
    while not stop_event.is_set() and cli_ready.is_set():
        packet = packet_queue.get()
        try:
            detector.process_packet(packet)
        finally:
            packet_queue.task_done()
        
        
        
        