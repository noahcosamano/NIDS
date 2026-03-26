from classes.packet import Packet
from utilities.block import block_ip, unblock_ip
from utilities.gateway import get_gateway
from logs.log import add_to_log
import time

def detect_scan(packet_queue, interval, quantity, cooldown):
    message = ""
    gateway = get_gateway()
    last_alert = {}
    activity = {}

    while True:
        unblock_ip()
        packet: Packet = packet_queue.get()
 
        now = packet.timestamp
        src_ip = packet.src_ip
        dst_port = packet.dst_port
        flags = packet.flags

        if not src_ip or not dst_port:
            packet_queue.task_done()
            continue
        
        if not (flags and "SYN" in flags and "ACK" not in flags):
            packet_queue.task_done()
            continue

        if src_ip not in activity:
            activity[src_ip] = []

        activity[src_ip].append((now, dst_port, flags))

        cutoff = now - interval
        
        activity[src_ip] = [(t, p, f) for (t, p, f) in activity[src_ip] if t >= cutoff]

        unique_ports = {p for (_, p, _) in activity[src_ip]}
        
        total_packets = len(activity[src_ip])

        if gateway is not None and packet.src_ip == gateway:
            packet_queue.task_done()
            continue
        
        elif packet.src_ip is not None and packet.src_ip.startswith("128."):
            packet_queue.task_done()
            continue
        
        elif len(unique_ports) >= quantity and total_packets >= quantity:
            last = last_alert.get(src_ip, 0)

            if now - last < cooldown:
                packet_queue.task_done()
                continue

            last_alert[src_ip] = now
            
            message += f"\n{time.ctime()}\nPort Scan\n"
            message += f"Source IP: {src_ip}\n"
            message += "\n".join(
                    f"{time.ctime(t)} | Port: {p} | Flags: {f}"
                    for i, (t, p, f) in enumerate(activity[src_ip], start=1)
                )
            message += f"\nBlocking IP: {src_ip}\n"
            message += "-" * 50
            add_to_log(message, "detection_log.txt")
            
            #block_ip(src_ip)
            activity[src_ip] = []

        packet_queue.task_done()