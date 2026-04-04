from capture.config.config import tcp_service_ports, udp_service_ports
from capture.classes.PyPacket import PyPacket
from utils.ui_helpers import clear
from queue import Empty
import msvcrt
import os
import time

def execute(packet_queue, target, wait_ms, stop_event):
    # If a string is passed, it must be protocol filtered and this will execute
    if isinstance(target, str):
        clear()
        print(f"\nListening for {target} packets (delay={wait_ms}ms)...")
        view_proto(packet_queue, target, stop_event, wait_ms)
    else:
        # Otherwise it must be port filtered and this will execute
        clear()
        print(f"\nListening on port {target} (delay={wait_ms}ms)...")
        view_port(packet_queue, target, stop_event, wait_ms)
        
# NOTE: The two functions below need to be combined into one

# Function called if a protocol is passed into "view"
def view_proto(packet_queue, proto, stop_event, wait_ms: int):
    selected_proto = proto.upper()
    
    udp_names = set(udp_service_ports.values())
    tcp_names = set(tcp_service_ports.values())
    
    # Converts milliseconds into seconds
    wait_seconds = wait_ms / 1000

    # This checks for keyboard input in order to break from currently executing command
    while msvcrt.kbhit():
        msvcrt.getch()

    # To break from currently executing command
    print("\nPress ANY key to stop...\n")

    # Stop event to end current command
    while not stop_event.is_set():
        if msvcrt.kbhit():
            msvcrt.getch()
            stop_event.set()
            clear()
            break
        
        if packet_queue.qsize() > 1000:
            print(f"--- WARNING: Queue Backlog! ({packet_queue.qsize()} packets waiting) ---")

        try:
            packet = packet_queue.get(timeout=0.1)
        except Empty:
            continue
        
        is_udp_match = (selected_proto == "UDP" and (packet.protocol == "UDP" or packet.protocol in udp_names))
        is_tcp_match = (selected_proto == "TCP" and (packet.protocol == "TCP" or packet.protocol in tcp_names))
        is_exact_match = (packet.protocol == selected_proto)

        # Only prints packet if the protocol matches user input, user can type ALL to view all packets
        if selected_proto == "ALL" or is_udp_match or is_tcp_match or is_exact_match:
            print(packet)
            
            # So terminal does not clog up under high traffic, if the user decides to use
            if wait_seconds > 0:
                time.sleep(wait_seconds)
                
# Function called if port is passed into "view"
def view_port(packet_queue, port, stop_event, wait_ms: int):
    # function runs identically to above function, view above for comments
    # I intend to combine the two into one in attempt to limit redundancy
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
        
        if packet_queue.qsize() > 1000:
            print(f"--- WARNING: Queue Backlog! ({packet_queue.qsize()} packets waiting) ---")

        try:
            packet: PyPacket = packet_queue.get_nowait()
        except Empty:
            continue

        if packet.src_port == port or packet.dst_port == port:
            print(packet)
            
            if wait_seconds > 0:
                time.sleep(wait_seconds)