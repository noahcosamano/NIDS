import ctypes

"""
This is the packet struct that was created and filled in C program. This is just so 
the python program knows what the C struct looks like and can convert to PyPacket.
"""

class CPacket(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("src_mac", ctypes.c_uint8 * 6),
        ("dst_mac", ctypes.c_uint8 * 6),
        ("src_ip", ctypes.c_uint8 * 16),
        ("dst_ip", ctypes.c_uint8 * 16),
        ("is_ipv6", ctypes.c_uint8),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("app_protocol", ctypes.c_uint8),
        ("type", ctypes.c_uint16),
        ("tcp_flags", ctypes.c_uint8),
        ("tv_sec", ctypes.c_longlong),
        ("tv_usec", ctypes.c_longlong),
        ("payload_len", ctypes.c_uint32),
        ("payload", ctypes.c_ubyte * 1500),
    ]