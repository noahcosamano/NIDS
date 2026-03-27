from dataclasses import dataclass
from typing import Optional

@dataclass
class Packet:
    dst_mac: Optional[str]     # Primarily for logging purposes 
    src_mac: Optional[str]     # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    protocol: Optional[str]
    type: Optional[int]        # If applicable, will track ICMP request vs. reply
    src_ip: Optional[str]      # Used in synergy with dst_port to track traffic frequency
    dst_ip: Optional[str]      # Used to detect an ICMP sweep
    src_port: Optional[int]    
    dst_port: Optional[int]    # Used in synergy with src_ip to track traffic frequency
    flags: Optional[str]       # Used to detect different types of TCP scans (ie. SYN, XMAS, NULL, etc.)
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
            parts.append(f"Flags={self.flags}")

        # ICMP type
        if self.protocol == "ICMP" and self.type is not None:
            parts.append(f"Type={self.type}")

        return " | ".join(parts)