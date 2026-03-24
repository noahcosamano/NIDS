from packet import Packet
from block import block_ip, unblock_ip
from gateway import get_gateway
from queue import Queue

def detect_sweep(packet_queue: Queue, interval, quantity, cooldown):
    gateway = get_gateway()
    last_alert = {}
    activity = {}
    
    while True: 
        unblock_ip()
        packet: Packet = packet_queue.get()
        
        now = packet.timestamp
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        protocol = packet.protocol
        
        if not src_ip:
            packet_queue.task_done()
            continue
        
        if packet.type != 8:
            continue
        
        if src_ip not in activity:
            activity[src_ip] = []
            
        activity[src_ip].append((now,dst_ip))
        
        cutoff = now - interval
        
        activity[src_ip] = [(t, d) for (t, d) in activity[src_ip] if t >= cutoff]
                
        unique_dst = {dst for (_, dst) in activity[src_ip]}
        
        if gateway is not None and packet.src_ip == gateway:
            packet_queue.task_done()
            continue
        
        elif packet.src_ip is not None and packet.src_ip.startswith("127."):
            packet_queue.task_done()
            continue
        
        elif len(unique_dst) >= quantity:
            last = last_alert.get(src_ip, 0)

            if now - last < cooldown:
                packet_queue.task_done()
                continue

            last_alert[src_ip] = now
            
            print("\n🚨 ICMP SWEEP DETECTED 🚨")
            print(f"Source IP: {src_ip}")
            print(f"{len(unique_dst)}+ addresses pinged in {interval} seconds")

            print(f"Blocking IP: {src_ip}")
            block_ip(src_ip)
            activity[src_ip] = []

        packet_queue.task_done()
        
        