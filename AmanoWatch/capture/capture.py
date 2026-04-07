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

# I don't think this function is necessary, in the future I intend on scrapping PyPackets entirely
# because it's a lot of overhead time for the system
def convert_to_pypacket(protocol, type, flags, src_mac, dst_mac, src_ip, dst_ip,
                        src_port, dst_port, query, query_len, timestamp):
    
    pypacket = PyPacket(dst_mac, src_mac, protocol, type, src_ip, dst_ip, 
                   src_port, dst_port, flags, query, query_len, timestamp)
    
    return pypacket

def queue(arp_queue, dns_queue, honey_port_queue, fast_scan_queue, slow_scan_queue, icmp_queue, cli_queue, packet: PyPacket):
    cli_queue.put(packet)
    
    if packet.protocol == "ARP":
        arp_queue.put(packet)
    elif packet.protocol == "DNS":
        dns_queue.put(packet)
    elif packet.protocol in ("TCP", "UDP"):
        fast_scan_queue.put(packet)
        slow_scan_queue.put(packet)
        honey_port_queue.put(packet)
    elif packet.protocol == "ICMP":
        icmp_queue.put(packet)

def begin_capture(device, arp_queue, dns_queue, honey_port_queue, fast_scan_queue, 
                  slow_scan_queue, icmp_queue, cli_queue, stop_event, cli_ready):
    PCAP_ERRBUF_SIZE = 256 # Size of buffer in bytes
    # This is the error buffer passed into InitCapture in dll so python can see error messages
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    
    # I should make this part of the get_dll_path function since it's repeated in many modules
    dll_path = get_dll_path("capture.dll")
    try:
        lib = ctypes.CDLL(dll_path, errbuf)
    except OSError as e:
        error(f"DLL not found at {dll_path}")
        return

    # Defines C argument types for each function
    lib.InitCapture.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    # Defines C return types for each function
    lib.InitCapture.restype = ctypes.c_int
    
    lib.GetNextPacketCache.argtypes = [ctypes.POINTER(CPacket)]
    lib.GetNextPacketCache.restype = ctypes.c_int
    
    lib.CloseCapture.argtypes = []
    lib.CloseCapture.restype = None

    # Attempt to open capture handle from C.
    if not lib.InitCapture(device, errbuf):
        error(errbuf)
        return

    cpacket = CPacket()
    
    packet_batch_size = 20 # Rather than bouncing back and forth with each packet captured, C sends 50 packets at a time to python
    packet_array = (CPacket * packet_batch_size)()

    try:
        while not stop_event.is_set() and cli_ready.is_set():
            # GetNextPacket called from capture.c in dll, return code stores as result
            count = lib.GetNextPacketCache(packet_array) # Amount of packets in the cache returned by capture.c
            
            if count > 0:
                for i in range(count):
                    cpacket = packet_array[i]
                    
                    src_ip = format_ip(cpacket.src_ip, cpacket.is_ipv6)
                    dst_ip = format_ip(cpacket.dst_ip, cpacket.is_ipv6)
                    flags = format_flags(cpacket.tcp_flags)
                    src_mac = format_mac(cpacket.src_mac)
                    dst_mac = format_mac(cpacket.dst_mac)
                    raw_payload = None
                    payload_len = None
                    
                    try:
                        if cpacket.payload_len > 0:
                            raw_payload = ctypes.string_at(cpacket.payload, cpacket.payload_len)
                            payload_len = cpacket.payload_len
                            
                    except Exception as e:
                        error(f"Failed to read payload: {e}")
                    
                    # Protocol has to be assigned last since fields like payload are used in defining protocol
                    protocol = parse_protocol(cpacket.protocol, cpacket.app_protocol)
                
                    pypacket = convert_to_pypacket(protocol, cpacket.type, flags, src_mac, 
                                                dst_mac,src_ip, dst_ip, cpacket.src_port,
                                                cpacket.dst_port, raw_payload, payload_len, cpacket.tv_sec)
                
                    queue(arp_queue, dns_queue, honey_port_queue, fast_scan_queue, slow_scan_queue, icmp_queue, cli_queue, pypacket)

            elif count < 0: # Abnormal failure, tell the user and close capture
                error(errbuf)
                break

    except KeyboardInterrupt:
        print("\nStopping capture...")
    finally:
        lib.CloseCapture() # CloseCapture called from capture.c, closes capture handle created