"""
AmanoWatch GUI — Capture Bridge
Runs the real capture + detection threads and emits Qt signals
so the GUI can update safely from the main thread.

Drop-in: just instantiate CaptureBridge, connect signals, call start().
"""

import threading
import queue
import time
from PyQt6.QtCore import QObject, pyqtSignal

# ── Try to import real AmanoWatch modules ──────────────────────────────────────
# If they're not on sys.path yet, the bridge runs in DEMO mode with fake packets.
try:
    from capture.capture import begin_capture
    from capture.classes.PyPacket import PyPacket
    from detect.port_scan import detect_port_scan
    from detect.icmp_sweep import detect_sweep
    from detect.arp_spoof import detect_arp_spoof
    from detect.dns_tunnel import detect_dns_tunnel
    REAL_CAPTURE = True
except ImportError:
    REAL_CAPTURE = False
    # Minimal stub so the rest of the file typechecks cleanly
    class PyPacket:
        def __init__(self, **kw):
            for k,v in kw.items(): setattr(self,k,v)


# ── Bridge ─────────────────────────────────────────────────────────────────────
class CaptureBridge(QObject):
    """
    Emits:
        packet_received(PyPacket)   – every captured packet
        alert_fired(str, str, str)  – (severity, title, detail)
        stats_updated(dict)         – periodic stats snapshot
    """
    packet_received = pyqtSignal(object)
    alert_fired     = pyqtSignal(str, str, str)   # severity, title, body
    stats_updated   = pyqtSignal(dict)

    def __init__(self, device_path: str = "", device_name: str = "", parent=None):
        super().__init__(parent)
        self.device_path  = device_path
        self.device_name = device_name
        self.stop_event   = threading.Event()
        self._threads     = []
        self._pkt_count   = 0
        self._drop_count  = 0
        self._proto_counts= {}
        self._lock        = threading.Lock()

        # Detection enable flags (toggled from GUI)
        self.detect_fast_scan  = True
        self.detect_slow_scan  = True
        self.detect_sweep      = True
        self.detect_arp        = True
        self.detect_dns_tunnel = False

    # ── Public API ─────────────────────────────────────────────────────────────
    def start(self):
        self.stop()
        self.stop_event.clear()
        with self._lock:
            self._pkt_count = 0
            self._drop_count = 0
            self._proto_counts = {}
        if REAL_CAPTURE and self.device_path:
            self._start_real()
        else:
            #self._start_demo()
            ...
        self._start_stats_timer()

    def stop(self):
        self.stop_event.set()
        for t in self._threads:
            t.join(timeout=1.0)
        self._threads.clear()

    # ── Real capture ───────────────────────────────────────────────────────────
    def _start_real(self):
        cli_q    = queue.Queue()
        fast_q   = queue.Queue()
        slow_q   = queue.Queue()
        icmp_q   = queue.Queue()
        arp_q    = queue.Queue()
        dns_q    = queue.Queue()
        ready    = threading.Event(); ready.set()
        device   = self.device_name

        def _capture():
            from capture.capture import begin_capture
            begin_capture(
                self.device_path.encode(),
                arp_q, dns_q, fast_q, slow_q, icmp_q, cli_q,
                self.stop_event, ready
            )

        def _drain(q):
            while not self.stop_event.is_set():
                try:
                    pkt = q.get(timeout=0.1)
                    self._on_packet(pkt)
                except queue.Empty:
                    continue
                
        def _emit_alert(severity, title, detail):
            self.alert_fired.emit(severity, title, detail)

        def _fast_scan():
            detect_port_scan(device, fast_q, 10, 20, 30, self.stop_event, ready, alert_callback=_emit_alert)
        def _slow_scan():
            detect_port_scan(device, slow_q, 60, 50, 30, self.stop_event, ready, alert_callback=_emit_alert)
        def _sweep():
            detect_sweep(icmp_q, 5, 10, 300, self.stop_event, ready)
        def _arp():
            detect_arp_spoof(arp_q, 30, self.stop_event, ready, alert_callback=_emit_alert)
        def _dns():
            detect_dns_tunnel(dns_q, self.stop_event, ready, alert_callback=_emit_alert)

        targets = [_capture, lambda: _drain(cli_q), _fast_scan, _slow_scan, _arp]
        for fn in targets:
            t = threading.Thread(target=fn, daemon=True)
            t.start()
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
                with self._lock:
                    cur = self._pkt_count
                    pps = cur - prev
                    prev = cur
                    snap = {
                        "total":  cur,
                        "dropped":self._drop_count,
                        "pps":    pps,
                        "protos": dict(self._proto_counts),
                    }
                self.stats_updated.emit(snap)

        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        self._threads.append(t)
