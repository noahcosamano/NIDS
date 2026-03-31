from network.get_devices import get_devices
from utils.ui_helpers import error, clear
import msvcrt

def execute(stop_event):
    clear()
    devices = get_devices()
    
    if not devices:
        error("Could not find any devices")
    
    print("\n" + "="*40)
    print("AVAILABLE NETWORK DEVICES:")
    print("="*40)
    
    # IF YOUR C CODE RETURNS A COMMA-SEPARATED LIST, SPLIT IT:
    for i, dev in enumerate(devices.split('|'), 1):
        if dev.strip():
            print(f"{i}. {dev.strip()}")

    print("="*40)
    
    # This checks for keyboard input in order to break from currently executing command
    while msvcrt.kbhit():
        msvcrt.getch()

    # To break from currently executing command
    print("\nPress ANY key to exit...\n")

    # Stop event to end current command
    while not stop_event.is_set():
        if msvcrt.kbhit():
            msvcrt.getch()
            stop_event.set()
            clear()
            break