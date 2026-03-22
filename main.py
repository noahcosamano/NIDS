import threading
import queue
import time
from capture import capture
from detect_scan import detect_scan

loopback = r'\Device\NPF_Loopback'
wifi = "Wi-Fi"

def main():
    fast_scan_packet_queue = queue.Queue()
    slow_scan_packet_queue = queue.Queue()

    capture_thread = threading.Thread(
        target=capture,
        args=(wifi, [fast_scan_packet_queue, slow_scan_packet_queue]),
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

    capture_thread.start()
    fast_scan_thread.start()
    slow_scan_thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down...")

    print("Program terminating...")
    
    capture_thread.join()
    fast_scan_thread.join()
    slow_scan_thread.join()

main()