from cli.start import start_cli
from capture.capture import begin_capture
from detect.port_scan import detect_port_scan
from detect.icmp_sweep import detect_sweep
from detect.dns_tunnel import detect_dns_tunnel
from detect.arp_spoof import detect_arp_spoof
import threading
import queue
import time

"""
Author: Noah Cosamano

Date: April 2, 2026

This is the command line interface for AmanoWatch, I currently recommend using the CLI still as the GUI
is still a heavy work-in-progress, many bugs (found and unfound) still exist, along with performance reduction.

At the current moment in time, AmanoWatch has strong support for port scan detection and packet capturing. 
ARP spoofing, DNS tunneling, and ICMP sweeping are still heavy works in progress and still need a lot of work.
"""

# Stores the device being used for capturing traffic, allows the user to select the device on startup.
# I intend on adding a feature/command that allows device to be changed mid capture. This was done originally
# and then scrapped due to unknown bugs, so this shared_content is still a remnant of that system.           
shared_content = {}

stop_event = threading.Event() # Ends all threads when ctrl+c is pressed for debugging, or 'exit' in cli
cli_ready_event = threading.Event() # Tells all other threads that the user has selected a device to capture on                 
  
def main():
    # All detectors and cli have their own packet queue to prevent race conditions and packet loss between queues
    cli_packet_queue = queue.Queue() 
    fast_scan_packet_queue = queue.Queue()
    slow_scan_packet_queue = queue.Queue()
    arp_spoof_packet_queue = queue.Queue()
    sweep_packet_queue = queue.Queue()
    dns_tunnel_packet_queue = queue.Queue()
    
    # All threads are set to daemon=True to end when program ends
    # All thread names are for debugging
    cli_thread = threading.Thread(
        target=start_cli,
        args=(cli_packet_queue, stop_event, cli_ready_event, shared_content),
        name="CLI",
        daemon=True
    )
    
    cli_thread.start() # CLI thread is started first so user can decide which device to capture on
    cli_ready_event.wait() # Wait for the event to be set, this means user has selected device
    device_path = shared_content["device_path"].encode("utf-8") # e.g. "\Device\NPF_Loopback"
    device_name = shared_content["device_name"]

    capture_thread = threading.Thread(
        target=begin_capture,
        args=(
            device_path, 
            [cli_packet_queue, fast_scan_packet_queue, slow_scan_packet_queue, 
            sweep_packet_queue, arp_spoof_packet_queue, dns_tunnel_packet_queue], 
            stop_event, cli_ready_event
        ),
        name="CAPTURE",
        daemon=True
    )
    
    fast_scan_thread = threading.Thread( # Detects fast port scan (20 hits in 10 seconds)
        target=detect_port_scan,
        # queue, interval, quantity, cooldown, stop event
        args=(device_name, fast_scan_packet_queue, 10, 20, 30, stop_event, cli_ready_event),
        name="FAST-SCAN",
        daemon=True
    )
    
    # I intend on combining the two somehow
    
    slow_scan_thread = threading.Thread( # Detects slow port scan (50 hits in 60 seconds
        target=detect_port_scan,
        # queue, interval, quantity, cooldown, stop event, cli ready event
        args=(device_name, slow_scan_packet_queue, 60, 50, 30, stop_event, cli_ready_event),
        name="SLOW-SCAN",
        daemon=True
    )
    
    sweep_thread = threading.Thread( # Sweep thread needs to be reprogrammed entirely,
                                     # very deprecated compared to rest of program
        target=detect_sweep,
        # queue, interval, quantity, cooldown, stop event, cli ready event
        args=(sweep_packet_queue, 5, 10, 30, stop_event, cli_ready_event),
        name="SWEEP",
        daemon=True
    )
    
    arp_spoof_thread = threading.Thread(
        target=detect_arp_spoof, 
        # queue, cooldown, stop event, cli ready event
        args=(arp_spoof_packet_queue, 30, stop_event, cli_ready_event),
        name="ARP SPOOF",
        daemon=True
    )
    
    dns_tunnel_thread = threading.Thread( # Many false positives right now, needs a lot of work
        target=detect_dns_tunnel,
        # queue, stop event, cli ready event
        # NOTE: No cooldown on dns tunnel since you'd probably want to see payload of each packet no matter how often
        args=(dns_tunnel_packet_queue, stop_event, cli_ready_event),
        name="DNS TUNNEL",
        daemon=True
    )

    # Need to find a way to prevent so many threads being used, going to slow program
    capture_thread.start()
    fast_scan_thread.start()
    slow_scan_thread.start()
    sweep_thread.start()
    arp_spoof_thread.start()
    #dns_tunnel_thread.start()
    
    try:
        while cli_thread.is_alive():
            time.sleep(0.1) 
    except KeyboardInterrupt: # Shut down entire program when ctrl+c is pressed for debugging
        return
    finally:
        print("\nShutting down...")
        # Set stop event so all threads stop running, program shuts down
        stop_event.set()
        
        # Join gives threads a small window to finish current process to ensure cleanup
        capture_thread.join(timeout=1)
        fast_scan_thread.join(timeout=1)
        slow_scan_thread.join(timeout=1)
        sweep_thread.join(timeout=1)
        arp_spoof_thread.join(timeout=1)
        #dns_tunnel_thread.join(timeout=1)

main()