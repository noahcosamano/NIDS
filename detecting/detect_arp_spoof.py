from configurations.packet import Packet
from utilities.block import unblock_mac, block_mac
from logs.log import add_to_log
import time

class ArpSpoof:
    def __init__(self, packet_queue, cooldown):
        self.packet_queue = packet_queue
        self.cooldown = cooldown
        self.arp_table = {}
        
    def process_packet(self, packet: Packet):
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
        add_to_log(message, "logs/detection_log.txt")
        
def detect_arp_spoof(packet_queue, cooldown):
    detector = ArpSpoof(packet_queue, cooldown)
    
    while True:
        unblock_mac()
        packet = packet_queue.get()
        try:
            detector.process_packet(packet)
        finally:
            packet_queue.task_done()
        
        