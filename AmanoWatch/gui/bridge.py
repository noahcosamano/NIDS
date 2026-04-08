"""
AmanoWatch GUI — Capture Bridge
Runs the real capture + detection threads and emits Qt signals
so the GUI can update safely from the main thread.

Each detector has its own stop event so it can be individually
disabled/enabled at runtime without touching the capture thread.
"""

import threading
import queue
import time
from PyQt6.QtCore import QObject, pyqtSignal

from capture.capture import begin_capture
from capture.classes.PyPacket import PyPacket
from detect.port_scan import detect_port_scan
from detect.icmp_sweep import detect_sweep
from detect.arp_spoof import detect_arp_spoof
from detect.dns_tunnel import detect_dns_tunnel
from detect.honey_ports import detect_honey_port_connection

# Real pcap_stats() wrapper — returns (recv, drop, ifdrop)
try:
    from network.capture_stats import get_capture_stats
except ImportError:
    def get_capture_stats():
        return (0, 0, 0)


DETECTOR_KEYS = ("fast_scan", "slow_scan", "sweep", "arp", "dns_tunnel", "honey_port")


# ── Bridge ─────────────────────────────────────────────────────────────────────
class CaptureBridge(QObject):
    """
    Emits:
        packet_received(PyPacket)   – every captured packet
        alert_fired(str, str, str)  – (severity, title, detail)
        stats_updated(dict)         – periodic stats snapshot
    """
    packet_received = pyqtSignal(object)
    alert_fired     = pyqtSignal(str, str, str)
    stats_updated   = pyqtSignal(dict)

    def __init__(self, device_path: str = "", device_name: str = "", parent=None):
        super().__init__(parent)
        self.device_path  = device_path
        self.device_name  = device_name
        self.stop_event   = threading.Event()
        self._threads     = []
        self._pkt_count   = 0
        self._drop_count  = 0
        self._ifdrop_count= 0
        self._pcap_recv   = 0
        self._proto_counts= {}
        self._lock        = threading.Lock()

        # Per-detector stop events.
        self._det_stops = {k: threading.Event() for k in DETECTOR_KEYS}

        # Per-detector queues — kept alive across restarts.
        self._det_queues = {
            "fast_scan":  queue.Queue(),
            "slow_scan":  queue.Queue(),
            "sweep":      queue.Queue(),
            "arp":        queue.Queue(),
            "dns_tunnel": queue.Queue(),
            "honey_port": queue.Queue(),
        }
        self._det_threads = {k: None for k in DETECTOR_KEYS}
        self._cli_q = None

        self._enabled = {k: True for k in DETECTOR_KEYS}

    # ── Public API ─────────────────────────────────────────────────────────────
    def start(self):
        self.stop()
        self.stop_event.clear()
        for ev in self._det_stops.values():
            ev.clear()
        with self._lock:
            self._pkt_count    = 0
            self._drop_count   = 0
            self._ifdrop_count = 0
            self._pcap_recv    = 0
            self._proto_counts = {}

        if not self.device_path:
            return

        self._start_capture()
        for key in DETECTOR_KEYS:
            if self._enabled[key]:
                self._start_detector(key)
        self._start_stats_timer()

    def stop(self):
        self.stop_event.set()
        for ev in self._det_stops.values():
            ev.set()
        for t in self._threads:
            t.join(timeout=1.0)
        self._threads.clear()
        self._det_threads = {k: None for k in DETECTOR_KEYS}

    def set_detector_enabled(self, key: str, enabled: bool):
        if key not in self._enabled:
            return
        if self._enabled[key] == enabled:
            return
        self._enabled[key] = enabled

        if enabled:
            q = self._det_queues[key]
            try:
                while True:
                    q.get_nowait()
            except queue.Empty:
                pass
            self._det_stops[key].clear()
            if self.device_path and not self.stop_event.is_set():
                self._start_detector(key)
        else:
            self._det_stops[key].set()
            t = self._det_threads.get(key)
            if t is not None:
                t.join(timeout=1.0)
            self._det_threads[key] = None

    # ── Capture thread ─────────────────────────────────────────────────────────
    def _start_capture(self):
        self._cli_q = queue.Queue()
        ready = threading.Event()
        ready.set()

        def _capture_real():
            begin_capture(
                self.device_path.encode(),
                self._det_queues["arp"],
                self._det_queues["dns_tunnel"],
                self._det_queues["honey_port"],
                self._det_queues["fast_scan"],
                self._det_queues["slow_scan"],
                self._det_queues["sweep"],
                self._cli_q,
                self.stop_event,
                ready
            )

        def _drain_cli():
            while not self.stop_event.is_set():
                try:
                    pkt = self._cli_q.get(timeout=0.1)
                    self._on_packet(pkt)
                except queue.Empty:
                    continue

        for fn in (_capture_real, _drain_cli):
            t = threading.Thread(target=fn, daemon=True)
            t.start()
            self._threads.append(t)

    # ── Detector threads ───────────────────────────────────────────────────────
    def _start_detector(self, key: str):
        if self._det_threads.get(key) is not None:
            return

        stop_ev = self._det_stops[key]
        ready = threading.Event()
        ready.set()
        device = self.device_name

        def _emit_alert(severity, title, detail):
            if not stop_ev.is_set():
                self.alert_fired.emit(severity, title, detail)

        q = self._det_queues[key]

        if key == "fast_scan":
            target = lambda: detect_port_scan(
                device, q, 10, 20, 30, stop_ev, ready, alert_callback=_emit_alert)
        elif key == "slow_scan":
            target = lambda: detect_port_scan(
                device, q, 60, 50, 30, stop_ev, ready, alert_callback=_emit_alert)
        elif key == "sweep":
            target = lambda: detect_sweep(q, 5, 10, 300, stop_ev, ready)
        elif key == "arp":
            target = lambda: detect_arp_spoof(
                q, 30, stop_ev, ready, alert_callback=_emit_alert)
        elif key == "dns_tunnel":
            target = lambda: detect_dns_tunnel(
                q, stop_ev, ready, alert_callback=_emit_alert)
        elif key == "honey_port":
            target = lambda: detect_honey_port_connection(
                device, q, stop_ev, ready, alert_callback=_emit_alert)
        else:
            return

        t = threading.Thread(target=target, daemon=True)
        t.start()
        self._det_threads[key] = t
        self._threads.append(t)

    # ── Internal ───────────────────────────────────────────────────────────────
    def _on_packet(self, pkt):
        with self._lock:
            self._pkt_count += 1
            proto = getattr(pkt, "protocol", "?") or "?"
            self._proto_counts[proto] = self._proto_counts.get(proto, 0) + 1
        self.packet_received.emit(pkt)

    def _start_stats_timer(self):
        def _loop():
            prev = 0
            while not self.stop_event.is_set():
                time.sleep(1)

                # Pull real pcap stats from the C layer
                recv, drop, ifdrop = get_capture_stats()

                with self._lock:
                    cur = self._pkt_count
                    pps = cur - prev
                    prev = cur

                    # Prefer pcap's own recv count when available
                    self._pcap_recv    = recv
                    self._drop_count   = drop
                    self._ifdrop_count = ifdrop

                    # Sum all detector queue depths + cli queue
                    q_depth = sum(q.qsize() for q in self._det_queues.values())
                    if self._cli_q is not None:
                        q_depth += self._cli_q.qsize()

                    snap = {
                        "total":   cur,
                        "recv":    recv,           # pcap's ps_recv
                        "dropped": drop + ifdrop,  # kernel + NIC drops
                        "kdrop":   drop,
                        "ifdrop":  ifdrop,
                        "pps":     pps,
                        "queue":   q_depth,
                        "protos":  dict(self._proto_counts),
                    }
                self.stats_updated.emit(snap)

        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        self._threads.append(t)