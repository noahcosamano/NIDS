from queue import Queue
import threading
from view_packets import view_proto

VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "IGMP", "ALL"}

def welcome():
    print("\n=== NIDS CLI ===")
    print("Type a protocol to filter traffic:")
    print("  TCP | UDP | ICMP | IGMP | ALL")
    print("Type 'exit' to quit.\n")
    
def start_cli(packet_queue: Queue):
    welcome()

    while True:
        proto = input("NIDS> ").strip().upper()

        if proto == "EXIT":
            print("Exiting CLI...")
            break

        if proto not in VALID_PROTOCOLS:
            print("Invalid protocol. Try again.")
            continue

        print(f"\nListening for {proto} packets...\n")

        viewer_thread = threading.Thread(
            target=view_proto,
            args=(packet_queue, proto),
            daemon=True
        )
        viewer_thread.start()