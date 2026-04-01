from capture.classes.PyPacket import PyPacket
from capture.classes.CPacket import CPacket
from capture.parse.ip import format_ip
from capture.parse.mac import format_mac
from capture.parse.flags import format_flags
from capture.parse.protocol import parse_protocol
from utils.load_dll import get_dll_path
from utils.ui_helpers import error
from queue import Queue
import ctypes

def convert_to_pypacket(protocol, type, flags, src_mac, dst_mac, src_ip, dst_ip,
                        src_port, dst_port, query, timestamp):
    
    pypacket = PyPacket(dst_mac, src_mac, protocol, type, src_ip, dst_ip, 
                   src_port, dst_port, flags, query, timestamp)
    
    return pypacket

def begin_capture(device, packet_queues: list[Queue[PyPacket]], stop_event, cli_ready):
    PCAP_ERRBUF_SIZE = 256 # Size of buffer in bytes
    # This is the error buffer passed into InitCapture in dll so python can see error messages
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    
    dll_path = get_dll_path()
    try:
        lib = ctypes.CDLL(dll_path, errbuf)
    except OSError as e:
        error(f"DLL not found at {dll_path}")
        return

    lib.InitCapture.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.InitCapture.restype = ctypes.c_int
    
    lib.GetNextPacketCache.argtypes = [ctypes.POINTER(CPacket)]
    lib.GetNextPacketCache.restype = ctypes.c_int
    
    lib.CloseCapture.argtypes = []
    lib.CloseCapture.restype = None

    if not lib.InitCapture(device, errbuf):
        error(errbuf)
        return

    cpacket = CPacket()
    
    packet_batch_size = 50
    packet_array = (CPacket * packet_batch_size)()

    try:
        while not stop_event.is_set() and cli_ready.is_set():
            # GetNextPacket called from capture.c in dll, return code stores as result
            count = lib.GetNextPacketCache(packet_array) 
            
            if count > 0:
                for i in range(count):
                    cpacket = packet_array[i]
                    
                    src_ip = format_ip(cpacket.src_ip, cpacket.is_ipv6)
                    dst_ip = format_ip(cpacket.dst_ip, cpacket.is_ipv6)
                    flags = format_flags(cpacket.tcp_flags)
                    src_mac = format_mac(cpacket.src_mac)
                    dst_mac = format_mac(cpacket.dst_mac)
                    protocol = parse_protocol(cpacket.protocol, cpacket.src_port, cpacket.dst_port)
                    raw_payload = None
                    
                    try:
                        if cpacket.payload_len > 0:
                            raw_payload = ctypes.string_at(cpacket.payload, cpacket.payload_len)
                    except Exception as e:
                        error(f"Failed to read payload: {e}")
                
                    pypacket = convert_to_pypacket(protocol, cpacket.type, flags, src_mac, 
                                                dst_mac,src_ip, dst_ip, cpacket.src_port,
                                                cpacket.dst_port, raw_payload, cpacket.tv_sec)
                
                    for q in packet_queues:
                        q.put(pypacket)

            elif count < 0: # Abnormal failure, tell the user and close capture
                error(errbuf)
                break

    except KeyboardInterrupt:
        print("\nStopping capture...")
    finally:
        lib.CloseCapture() # CloseCapture called from capture.c, closes capture handle created