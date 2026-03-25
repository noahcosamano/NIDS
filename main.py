import threading
import queue
import time
from capture import capture
from detect_scan import detect_scan
from detect_sweep import detect_sweep
from cli import start_cli

loopback = r'\Device\NPF_Loopback'
wifi = "Wi-Fi"

def main():
    cli_packet_queue = queue.Queue()
    fast_scan_packet_queue = queue.Queue()
    slow_scan_packet_queue = queue.Queue()
    sweep_packet_queue = queue.Queue()
    
    cli_thread = threading.Thread(
        target=start_cli,
        args=(cli_packet_queue,),
        daemon=False
    )

    capture_thread = threading.Thread(
        target=capture,
        args=(wifi, [cli_packet_queue, fast_scan_packet_queue, slow_scan_packet_queue, sweep_packet_queue]),
        daemon=False
    )

    fast_scan_thread = threading.Thread(
        target=detect_scan,
        args=(fast_scan_packet_queue, 10, 20, 30),
        daemon=False
    )
    
    slow_scan_thread = threading.Thread(
        target=detect_scan,
        args=(slow_scan_packet_queue, 60, 50, 30),
        daemon=False
    )
    
    sweep_thread = threading.Thread(
        target=detect_sweep,
        args=(sweep_packet_queue, 5, 10, 300),
        daemon=False
    )

    cli_thread.start()
    capture_thread.start()
    fast_scan_thread.start()
    slow_scan_thread.start()
    sweep_thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down...")

    print("Program terminating...")
    
    cli_thread.join()
    capture_thread.join()
    fast_scan_thread.join()
    slow_scan_thread.join()
    sweep_thread.join()

main()