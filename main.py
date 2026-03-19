import threading
import queue
from capture_packets import capture, build_packet_list
from detect_scan import detect_scan

def main():
    raw_packet_queue = queue.Queue()
    parsed_packet_queue = queue.Queue()
    stop_event = threading.Event()

    capture_thread = threading.Thread(
        target=capture,
        args=("Wi-Fi", raw_packet_queue, stop_event),
        daemon=True
    )

    parse_thread = threading.Thread(
        target=build_packet_list,
        args=(raw_packet_queue, parsed_packet_queue, stop_event),
        daemon=True
    )

    scan_thread = threading.Thread(
        target=detect_scan,
        args=(parsed_packet_queue, stop_event, 10, 20),
        daemon=True
    )

    capture_thread.start()
    parse_thread.start()
    scan_thread.start()

    stop_event.wait()

    print("Program terminating...")

main()