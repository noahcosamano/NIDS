import ctypes
from utils.load_dll import get_dll_path
from utils.ui_helpers import error, clear
from network.capture_stats import PcapStats
import msvcrt
   
def execute(stop_event):
    PCAP_ERRBUF_SIZE = 256 # Size of buffer in bytes
    # This is the error buffer passed into InitCapture in dll so python can see error messages
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    
    # Need to move all of this logic to get_dll_path, too repetitive
    dll_path = get_dll_path("capture.dll")
    try:
        lib = ctypes.CDLL(dll_path, errbuf)
    except OSError as e:
        error(f"DLL not found at {dll_path}")
        return
    
    stats = PcapStats()
    
    # GetStats is a default pcap function
    lib.GetStats(ctypes.byref(stats))
    
    clear()
    print(stats)
    
    # To break from currently executing command
    print("\nPress ANY key to exit...\n")
    
    # Stop event to end current command
    while not stop_event.is_set():
        if msvcrt.kbhit():
            msvcrt.getch()
            stop_event.set()
            clear()
            break