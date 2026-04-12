from capture.classes.PyPacket import PyPacket
from network.block_mac import unblock_mac, block_mac
from database.edit import add_detection
from threading import Event
from queue import Queue

class ArpSpoof:
    def __init__(self, packet_queue, cooldown, alert_callback=None):
        self.packet_queue = packet_queue
        self.cooldown = cooldown
        self.arp_table = {}
        self.last_alert = {} # source mac: timestamp
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
            self.spoof_detected(packet)
            
    def spoof_detected(self, packet: PyPacket):
        last_time = self.last_alert.get(packet.src_mac)
        if last_time and (packet.timestamp - last_time < self.cooldown):
            return

        self.last_alert[packet.src_mac] = packet.timestamp
        self.log_alert(packet, self.arp_table[packet.src_ip][0], packet.src_mac)
            
    def log_alert(self, packet: PyPacket, old_mac, new_mac):
        if self.alert_callback:
            self.alert_callback("critical", "ARP SPOOFING", f"{packet.src_ip} changed from {old_mac} to {new_mac}")
        
        summary = f"{packet.src_ip} changed MAC address from {old_mac} to {new_mac}"
        
        add_detection(
            detector_type="ARP Spoof", 
            severity="critical", 
            summary=summary, 
            src_ip=packet.src_ip, 
            src_mac=old_mac, 
            src_port=packet.src_port, 
            dst_ip=packet.dst_ip, 
            dst_mac=packet.dst_mac, 
            dst_port=packet.dst_port, 
            details=None)
        
def detect_arp_spoof(packet_queue: Queue, cooldown, stop_event: Event, cli_ready: Event, alert_callback=None):
    detector = ArpSpoof(packet_queue, cooldown, alert_callback=alert_callback)
    
    while not stop_event.is_set() and cli_ready.is_set():
        unblock_mac()
        packet = packet_queue.get()
        try:
            detector.process_packet(packet)
        finally:
            packet_queue.task_done()
        
        