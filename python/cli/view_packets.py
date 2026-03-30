import msvcrt
import time
import os
from queue import Empty
from configurations.packet import PyPacket

# Function called if a protocol is passed into "view"
def view_proto(packet_queue, proto, stop_event, wait_ms: int):
    selected_proto = proto.upper()
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
            os.system("cls")
            break

        try:
            packet = packet_queue.get(timeout=0.1)
        except Empty:
            continue

        # Only prints packet if the protocol matches user input, user can type ALL to view all packets
        if selected_proto == "ALL" or packet.protocol == selected_proto:
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

        try:
            packet: PyPacket = packet_queue.get_nowait()
        except Empty:
            continue

        if packet.src_port == port or packet.dst_port == port:
            print(packet)
            
            if wait_seconds > 0:
                time.sleep(wait_seconds)