from dataclasses import dataclass
from typing import Optional

@dataclass
class Packet:
    dst_mac: Optional[str]
    src_mac: Optional[str]
    protocol: Optional[str]
    type: Optional[int]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    flags: Optional[str]
    timestamp: float
    
    def __str__(self):
        parts = []

        # Protocol header
        parts.append(f"[{self.protocol}]")

        # IP layer
        if self.src_ip and self.dst_ip:
            parts.append(f"{self.src_ip} → {self.dst_ip}")

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