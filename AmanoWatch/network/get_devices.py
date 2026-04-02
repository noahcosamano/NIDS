import ctypes
from utils.load_dll import get_dll_path
from utils.ui_helpers import error

def get_devices():
    PCAP_ERRBUF_SIZE = 256
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    
    dll_path = get_dll_path("capture.dll")
    try:
        lib = ctypes.CDLL(dll_path)
    except OSError:
        error(f"DLL NOT FOUND AT {dll_path}")
        return

    # 1. DEFINE ARGUMENTS AND RETURN TYPES CORRECTLY
    # ASSUMING GetDevices RETURNS A char* (POINTER TO A STRING)
    lib.GetDevices.argtypes = [ctypes.c_char_p]
    lib.GetDevices.restype = ctypes.c_char_p 

    # 2. CALL THE FUNCTION
    devices_raw = lib.GetDevices(errbuf)

    # 3. CHECK FOR ERRORS
    if not devices_raw:
        # CONVERT THE BYTES IN ERRBUF TO A PYTHON STRING
        error_msg = errbuf.value.decode('utf-8', errors='ignore')
        error(f"PCAP ERROR: {error_msg}")
        return
    
    # 4. DECODE THE RESULT
    # C RETURNS BYTES; WE NEED A STRING
    devices_str = devices_raw.decode('utf-8', errors='ignore')
    
    return devices_str