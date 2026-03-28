from configurations.packet import Packet
from logs.log import report_to_webhook
import math
from collections import Counter 
import time

class DnsTunnel:
    def __init__(self, packet_queue):
        self.packet_queue = packet_queue
    
    def process_packet(self, packet: Packet):
        if packet.protocol != "DNS" or not packet.query:
            return
        
        if packet.query.endswith(".local."):
            return
        
        entropy = self.string_entropy(packet.query)
        
        if entropy > 4.0:
            message = f"\n{time.ctime()}\nDNS Tunnel\nSource IP: {packet.src_ip}\n"
            message += f"Query: {packet.query} | Entropy: {entropy}\n"
            message += f"Blocking {packet.src_ip} for 300 seconds\n"
            
            report_to_webhook("DNS Tunnel", message)
        
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
    
def detect_dns_tunnel(packet_queue, stop_event):
    detector = DnsTunnel(packet_queue)
    
    while not stop_event.is_set():
        packet = packet_queue.get()
        try:
            detector.process_packet(packet)
        finally:
            packet_queue.task_done()
        
        
        
        