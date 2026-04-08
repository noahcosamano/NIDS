import ctypes
import os


class PcapStats(ctypes.Structure):
    _fields_ = [
        ("ps_recv", ctypes.c_uint),    # Packets received by the filter
        ("ps_drop", ctypes.c_uint),    # Packets dropped by libpcap/driver buffer
        ("ps_ifdrop", ctypes.c_uint),  # Packets dropped by the interface/NIC
    ]

    def __str__(self):
        total_attempted = self.ps_recv + self.ps_drop + self.ps_ifdrop
        loss_pct = (self.ps_drop / total_attempted * 100) if total_attempted > 0 else 0

        stats_str = [
            "\n" + "=" * 40,
            "         CAPTURE STATISTICS",
            "=" * 40,
            f"Received by Capture:   {self.ps_recv}",
            f"Dropped (Buffer Full): {self.ps_drop}",
            f"Dropped (Interface):   {self.ps_ifdrop}",
            f"Packet Loss Rate:      {loss_pct:.2f}%",
            "=" * 40,
        ]
        return "\n".join(stats_str)


# ── DLL loader ────────────────────────────────────────────────────────────────
_DLL = None

def _load_dll():
    global _DLL
    if _DLL is not None:
        return _DLL

    # Adjust these paths to match where your capture DLL actually lives.
    candidates = [
        os.path.join(os.path.dirname(__file__), "capture.dll"),
        os.path.join(os.path.dirname(__file__), "..", "capture.dll"),
        os.path.join(os.path.dirname(__file__), "..", "capture", "capture.dll"),
        "capture.dll",
    ]
    for path in candidates:
        try:
            _DLL = ctypes.CDLL(path)
            _DLL.GetStats.argtypes = [ctypes.POINTER(PcapStats)]
            _DLL.GetStats.restype = ctypes.c_int
            return _DLL
        except OSError:
            continue
    return None


def get_capture_stats():
    """
    Returns (recv, drop, ifdrop) as ints.
    Returns (0, 0, 0) if the DLL isn't loaded or the capture hasn't started.
    """
    dll = _load_dll()
    if dll is None:
        return (0, 0, 0)

    stats = PcapStats()
    try:
        rc = dll.GetStats(ctypes.byref(stats))
    except Exception:
        return (0, 0, 0)

    if rc != 0:
        return (0, 0, 0)

    return (int(stats.ps_recv), int(stats.ps_drop), int(stats.ps_ifdrop))