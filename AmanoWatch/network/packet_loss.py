import ctypes

class PcapStats(ctypes.Structure):
    _fields_ = [
        ("ps_recv", ctypes.c_uint),   # Packets received by the filter
        ("ps_drop", ctypes.c_uint),   # Packets dropped by libpcap/driver buffer
        ("ps_ifdrop", ctypes.c_uint)  # Packets dropped by the interface/NIC
    ]

    def __str__(self):
        # Calculate loss percentage safely
        total_attempted = self.ps_recv + self.ps_drop + self.ps_ifdrop
        loss_pct = (self.ps_drop / total_attempted * 100) if total_attempted > 0 else 0
        
        stats_str = [
            "\n" + "="*40,
            "         CAPTURE STATISTICS",
            "="*40,
            f"Received by Capture:    {self.ps_recv}",
            f"Dropped (Buffer Full): {self.ps_drop}",
            f"Dropped (Interface):   {self.ps_ifdrop}",
            f"Packet Loss Rate:      {loss_pct:.2f}%",
            "="*40
        ]
        return "\n".join(stats_str)