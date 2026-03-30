import threading
import queue
import time
from utilities.packet_capture import capture
from detecting.detect_port_scan import detect_port_scan
from detecting.detect_sweep import detect_sweep
from detecting.detect_arp_spoof import detect_arp_spoof
from detecting.detect_dns_tunnel import detect_dns_tunnel
from cli.cli import start_cli
                            
# standard adapters for debugging                                          
loopback = b'\\Device\\NPF_Loopback'
wifi = b"\\Device\\NPF_{95DCD5E9-81B2-4BBB-BEC6-17C65D6ECD92}"

# Ends all threads when ctrl+c is pressed for debugging
stop_event = threading.Event()                 
  
def main():
    cli_packet_queue = queue.Queue()
    fast_scan_packet_queue = queue.Queue()
    slow_scan_packet_queue = queue.Queue()
    arp_spoof_packet_queue = queue.Queue()
    sweep_packet_queue = queue.Queue()
    dns_tunnel_packet_queue = queue.Queue()
    
    # All threads are set to daemon=True to end when program ends
    # all thread names are for debugging
    cli_thread = threading.Thread(
        target=start_cli,
        args=(cli_packet_queue, stop_event),
        name="CLI",
        daemon=True
    )

    # All packet queues are passed in so each event has its own queue to prevent race conditions
    capture_thread = threading.Thread(
        target=capture,
        args=(
            wifi, [cli_packet_queue, fast_scan_packet_queue, slow_scan_packet_queue, 
            sweep_packet_queue, arp_spoof_packet_queue, dns_tunnel_packet_queue], stop_event
        ),
        name="CAPTURE",
        daemon=True
    )

    fast_scan_thread = threading.Thread(
        target=detect_port_scan,
        # queue, interval, quantity, cooldown, stop event
        args=(fast_scan_packet_queue, 10, 20, 30, stop_event),
        name="FAST-SCAN",
        daemon=True
    )
    
    slow_scan_thread = threading.Thread(
        target=detect_port_scan,
        # queue, interval, quantity, cooldown, stop event
        args=(slow_scan_packet_queue, 60, 50, 30, stop_event),
        name="SLOW-SCAN",
        daemon=True
    )
    
    sweep_thread = threading.Thread(
        target=detect_sweep,
        # queue, interval, quantity, cooldown, stop event
        args=(sweep_packet_queue, 5, 10, 300, stop_event),
        name="SWEEP",
        daemon=True
    )
    
    arp_spoof_thread = threading.Thread(
        target=detect_arp_spoof,
        args=(arp_spoof_packet_queue, 30, stop_event),
        name="ARP SPOOF",
        daemon=True
    )
    
    dns_tunnel_thread = threading.Thread(
        target=detect_dns_tunnel,
        args=(dns_tunnel_packet_queue, stop_event),
        name="DNS TUNNEL",
        daemon=True
    )

    # Need to find a way to prevent so many threads being used, going to slow program
    cli_thread.start()
    capture_thread.start()
    fast_scan_thread.start()
    slow_scan_thread.start()
    sweep_thread.start()
    arp_spoof_thread.start()
    dns_tunnel_thread.start()
    
    try:
        while cli_thread.is_alive():
            time.sleep(0.1) 
    except KeyboardInterrupt:
        return
    finally:
        print("\nShutting down...")
        # Set stop event so all threads stop running, program shuts down
        stop_event.set()
        
        # Join gives threads a small window to finish current process to ensure cleanup
        capture_thread.join(timeout=1)
        fast_scan_thread.join(timeout=1)

main()