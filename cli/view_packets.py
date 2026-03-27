import msvcrt
import time
import os
from queue import Empty
from configurations.packet import Packet

def view_proto(packet_queue, proto, stop_event, wait_ms: int):
    selected_proto = proto.upper()
    wait_seconds = wait_ms / 1000

    while msvcrt.kbhit():
        msvcrt.getch()

    print("\nPress ANY key to stop...\n")

    while not stop_event.is_set():
        if msvcrt.kbhit():
            msvcrt.getch()
            stop_event.set()
            os.system("cls")
            break

        try:
            packet = packet_queue.get(timeout=0.1)
        except Empty:
            continue

        if selected_proto == "ALL" or packet.protocol == selected_proto:
            print(packet)
            
            if wait_seconds > 0:
                time.sleep(wait_seconds)
                
def view_port(packet_queue, port, stop_event, wait_ms: int):
    wait_seconds = wait_ms / 1000
    
    while msvcrt.kbhit():
        msvcrt.getch()

    print("\nPress ANY key to stop...\n")
    
    while not stop_event.is_set():
        if msvcrt.kbhit():
            msvcrt.getch()
            stop_event.set()
            os.system("cls")
            break

        try:
            packet: Packet = packet_queue.get_nowait()
        except Empty:
            continue

        if packet.src_port == port or packet.dst_port == port:
            print(packet)
            
            if wait_seconds > 0:
                time.sleep(wait_seconds)