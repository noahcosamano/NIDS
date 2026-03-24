from queue import Queue
from packet import Packet

def view_proto(packet_queue: Queue, proto: str):
    while True:
        packet: Packet = packet_queue.get()
        
        if packet.protocol == proto.upper():
            print(packet)
            
        packet_queue.task_done()