from capture.classes import PyPacket
from network.block_mac import unblock_mac, block_mac
from log.log import report_to_webhook
import time

class ArpSpoof:
    def __init__(self, packet_queue, cooldown, alert_callback=None):
        self.packet_queue = packet_queue
        self.cooldown = cooldown
        self.arp_table = {}
        self.alert_callback = alert_callback
        
    def process_packet(self, packet: PyPacket):
        now = packet.timestamp
        protocol = packet.protocol
        src_ip = packet.src_ip
        src_mac = packet.src_mac
        
        if not src_ip or not src_mac or protocol != "ARP":
            return
        
        if src_ip == "0.0.0.0":
            return
        
        if src_ip not in self.arp_table:
            self.arp_table[src_ip] = [src_mac, now]
        
        elif self.arp_table[src_ip][0] != src_mac:
            self.log_alert(src_ip, self.arp_table[src_ip][0], src_mac)
            
    def log_alert(self, ip, old_mac, new_mac):
        message = f"\n{time.ctime()}\nARP Spoof\n"
        message += f"{ip} changed from {old_mac} to {new_mac}\n"

        message += f"Blocking {new_mac} for 300 seconds\n" + "-"*50
        report_to_webhook("ARP Spoof", message)
        if self.alert_callback:
            self.alert_callback("critical", "ARP SPOOFING", f"{ip} changed from {old_mac} to {new_mac}")
        
def detect_arp_spoof(packet_queue, cooldown, stop_event, cli_ready, alert_callback=None):
    detector = ArpSpoof(packet_queue, cooldown, alert_callback=alert_callback)
    
    while not stop_event.is_set() and cli_ready.is_set():
        unblock_mac()
        packet = packet_queue.get()
        try:
            detector.process_packet(packet)
        finally:
            packet_queue.task_done()
        
        