from capture.classes import PyPacket
from network.block_ip import block_ip, unblock_ip
from network.get_gateway import get_gateway
from queue import Queue
import time

def detect_sweep(packet_queue: Queue, interval, quantity, cooldown, stop_event, cli_ready):
    message = ""
    gateway = get_gateway()
    last_alert = {}
    activity = {}
    
    while not stop_event.is_set() and cli_ready.is_set(): 
        unblock_ip()
        packet: PyPacket = packet_queue.get()
        
        now = packet.timestamp
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        type = packet.type
        
        if not src_ip:
            packet_queue.task_done()
            continue
        
        if type != 8:
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
            
            message += f"{time.ctime()}\nICMP Sweep\n"
            message += f"Source IP: {src_ip}\n"
            message += "\n".join(
                    f"{time.ctime(t)} | Address: {d}"
                    for (t, d) in activity[src_ip]
                )
            message += f"\nBlocking IP: {src_ip}\n"
    
            block_ip(src_ip)
            activity[src_ip] = []

        packet_queue.task_done()
        
        