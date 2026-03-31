import ctypes
from configurations.packet import PyPacket, Packet
from configurations.proto_nums import protocol_nums, tcp_service_ports, udp_service_ports
from utilities.format_fields import format_flags, format_ip, format_mac
from utilities.ui_helpers import error
from utilities.load_dll import get_dll_path
from queue import Queue

def get_protocol(protocol_num, src_port, dst_port):
    protocol = protocol_nums[protocol_num]
    if protocol == "TCP":
        protocol = tcp_service_ports.get(dst_port, tcp_service_ports.get(src_port, "TCP"))
    elif protocol == "UDP":
        protocol = udp_service_ports.get(dst_port, udp_service_ports.get(src_port, "UDP"))
    elif protocol == "ARP":
        return protocol
    elif protocol == "ICMPV6":
        return protocol
    else:
        protocol = protocol_nums.get(protocol, "UNKNOWN")
        
    return protocol
    
def convert_to_pypacket(protocol, type, flags, src_mac, dst_mac, src_ip, dst_ip,
                        src_port, dst_port, query, timestamp):
    
    pkt = PyPacket(dst_mac, src_mac, protocol, type, src_ip, dst_ip, 
                   src_port, dst_port, flags, query, timestamp)
    
    return pkt

def capture(device, packet_queues: list[Queue[PyPacket]], stop_event):
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
    
    lib.GetNextPacket.argtypes = [ctypes.POINTER(Packet)]
    lib.GetNextPacket.restype = ctypes.c_int
    
    lib.CloseCapture.argtypes = []
    lib.CloseCapture.restype = None

    if not lib.InitCapture(device, errbuf):
        error(errbuf)
        return

    CPacket = Packet()

    try:
        while not stop_event.is_set():
            # GetNextPacket called from capture.c in dll, return code stores as result
            result = lib.GetNextPacket(ctypes.byref(CPacket)) 
            
            if result == 1: # Success, so fill packet
                src_ip = format_ip(CPacket.src_ip, CPacket.is_ipv6)
                dst_ip = format_ip(CPacket.dst_ip, CPacket.is_ipv6)
                flags = format_flags(CPacket.tcp_flags)
                src_mac = format_mac(CPacket.src_mac)
                dst_mac = format_mac(CPacket.dst_mac)
                protocol = get_protocol(CPacket.protocol, CPacket.src_port, CPacket.dst_port)
                raw_payload = None
                
                try:
                    if CPacket.payload_len > 0:
                        raw_payload = ctypes.string_at(CPacket.payload, CPacket.payload_len)
                except Exception as e:
                    error(f"Failed to read payload: {e}")
            
                pypacket = convert_to_pypacket(protocol, CPacket.type, flags, src_mac, 
                                               dst_mac,src_ip, dst_ip, CPacket.src_port,
                                               CPacket.dst_port, raw_payload,CPacket.tv_sec)
                
                for q in packet_queues:
                    q.put(pypacket)

            elif result == 0: # Failure, just continue looping
                continue
            else: # Abnormal failure, tell the user and close capture
                error(errbuf)
                break

    except KeyboardInterrupt:
        print("\nStopping capture...")
    finally:
        lib.CloseCapture() # CloseCapture called from capture.c, closes capture handle created