from packet import Packet
from block import block_ip
import time

def detect_scan(packet_queue, stop_event, interval=10, quantity=20):
    activity = {}

    while not stop_event.is_set():
        packet: Packet = packet_queue.get()
 
        now = time.time()
        src_ip = packet.src_ip
        dst_port = packet.dst_port

        if not src_ip or not dst_port:
            packet_queue.task_done()
            continue

        if src_ip not in activity:
            activity[src_ip] = []

        activity[src_ip].append((now, dst_port))

        cutoff = now - interval
        activity[src_ip] = [
            (t, p) for (t, p) in activity[src_ip]
            if t >= cutoff
        ]

        unique_ports = {p for (_, p) in activity[src_ip]}

        if len(unique_ports) >= quantity:
            print("\n🚨 PORT SCAN DETECTED 🚨")
            print(f"Source IP: {src_ip}")
            print(f"{len(unique_ports)} ports hit in {interval} seconds")
            
            if packet.src_ip.startswith("127."):
                continue
            else:
                block_ip(src_ip)

            stop_event.set()

        packet_queue.task_done()