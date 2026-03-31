from dataclasses import dataclass
from typing import Optional
import ctypes

class Packet(ctypes.Structure):
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
        ("type", ctypes.c_uint16),
        ("tcp_flags", ctypes.c_uint8),
        ("tv_sec", ctypes.c_longlong),
        ("tv_usec", ctypes.c_longlong),
        ("payload_len", ctypes.c_uint32),
        ("payload", ctypes.POINTER(ctypes.c_uint8)),
    ]

@dataclass
class PyPacket:
    dst_mac: Optional[str]     # Primarily for logging purposes 
    src_mac: Optional[str]     # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    protocol: Optional[str]
    type: Optional[int]        # If applicable, will track ICMP request vs. reply
    src_ip: Optional[str]      # Used in synergy with dst_port to track traffic frequency
    dst_ip: Optional[str]      # Used to detect an ICMP sweep
    src_port: Optional[int]    
    dst_port: Optional[int]    # Used in synergy with src_ip to track traffic frequency
    flags: Optional[str]       # Used to detect different types of TCP scans (ie. SYN, XMAS, NULL, etc.)
    query: Optional[bytes]
    timestamp: float           # For logging or tracking traffic frequency
     
    def __str__(self):
        parts = []

        # Protocol header
        parts.append(f"[{self.protocol}]")

        # IP layer with optional MACs
        if self.src_ip and self.dst_ip:
            src = self.src_ip
            dst = self.dst_ip
            if self.src_mac:
                src += f" - {self.src_mac}"
            if self.dst_mac:
                dst += f" - {self.dst_mac}"
            parts.append(f"{src} → {dst}")

        # Ports (for TCP/UDP)
        if self.src_port is not None and self.dst_port is not None:
            parts.append(f"{self.src_port} → {self.dst_port}")

        # TCP flags
        if self.flags:
            parts.append(f"{self.flags}")

        # ICMP type
        if self.protocol == "ICMP" and self.type is not None:
            parts.append(f"Type={self.type}")

        return " | ".join(parts)