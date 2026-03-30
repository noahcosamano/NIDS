import ctypes
import os
from configurations.packet import PyPacket, Packet
from configurations.proto_nums import protocol_nums
from utilities.format_fields import format_flags, format_ip, format_mac
from queue import Queue
    
def convert_to_pypacket(protocol, type, flags, src_mac, dst_mac, src_ip, dst_ip,
                        src_port, dst_port, query, timestamp):
    
    pkt = PyPacket(dst_mac, src_mac, protocol, type, src_ip, dst_ip, 
                   src_port, dst_port, flags, query, timestamp)
    
    return pkt

def capture(device, packet_queues: list[Queue[PyPacket]], stop_event):
    # 2. Load the DLL
    # Make sure sniffer.dll is in the same folder as this script
    dll_path = os.path.abspath("release/packet-capture.dll")
    try:
        lib = ctypes.CDLL(dll_path)
    except OSError as e:
        print(f"Error: Could not load DLL at {dll_path}. \n{e}")
        return

    # 3. Define function signatures for the DLL exports
    lib.InitCapture.argtypes = [ctypes.c_char_p]
    lib.InitCapture.restype = ctypes.c_int
    
    lib.GetNextPacket.argtypes = [ctypes.POINTER(Packet)]
    lib.GetNextPacket.restype = ctypes.c_int
    
    lib.CloseCapture.argtypes = []
    lib.CloseCapture.restype = None

    # 4. Initialize Capture
    if not lib.InitCapture(device):
        print("Failed to initialize capture. Check device path or Admin privileges.")
        return

    CPacket = Packet()

    try:
        while not stop_event.is_set():
            # 5. Pull the next packet from the C DLL
            result = lib.GetNextPacket(ctypes.byref(CPacket))
            
            if result == 1:
                src_ip = format_ip(CPacket.src_ip, CPacket.is_ipv6)
                dst_ip = format_ip(CPacket.dst_ip, CPacket.is_ipv6)
                flags = format_flags(CPacket.tcp_flags)
                src_mac = format_mac(CPacket.src_mac)
                dst_mac = format_mac(CPacket.dst_mac)
                protocol = protocol_nums[CPacket.protocol]
                raw_payload = None
                
                # If you need to access the payload data:
                if CPacket.payload_len > 0:
                    # We MUST copy it immediately because the C buffer is transient
                    raw_payload = ctypes.string_at(CPacket.payload, CPacket.payload_len)
                    # Process your payload bytes here (e.g., raw_payload.hex())
            
                pypacket = convert_to_pypacket(protocol, CPacket.type, flags, src_mac, 
                                               dst_mac,src_ip, dst_ip, CPacket.src_port,
                                               CPacket.dst_port, raw_payload,CPacket.tv_sec)
                
                for q in packet_queues:
                    q.put(pypacket)

            elif result == 0:
                # Timeout - just loop again
                continue
            else:
                print("An error occurred in the capture handle.")
                break

    except KeyboardInterrupt:
        print("\nStopping capture...")
    finally:
        lib.CloseCapture()