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


# ── Demo packet generator (used when real capture is unavailable) ──────────────
'''import random, math
from collections import Counter

_PROTOS    = ["TCP","UDP","ICMP","DNS","HTTP","HTTPS","ARP","TLS","DHCP","QUIC"]
_PROTO_W   = [30,  20,   8,    15,   6,    10,    4,    3,   2,    2   ]
_PUB_IPS   = ["8.8.8.8","1.1.1.1","104.21.48.1","151.101.1.1",
               "185.199.108.1","93.184.216.34","172.217.14.1"]
_PRIV_PFXS = ["192.168.1.","10.0.0.","172.16.0.","192.168.0.","10.10.1."]
_FLAGS     = ["SYN","ACK","SYN ACK","FIN ACK","RST","PSH ACK","FIN",""]
_FLAG_W    = [15,  35,   20,      10,      5,   10,     3,   2  ]
_WELL_PORTS= [22,23,25,53,80,110,143,443,445,3389,8080]

def _wrandom(arr, weights):
    total = sum(weights)
    r = random.random() * total
    for item, w in zip(arr, weights):
        r -= w
        if r <= 0:
            return item
    return arr[-1]

def _rand_ip(public=False):
    if public or random.random() < 0.3:
        return random.choice(_PUB_IPS)
    return random.choice(_PRIV_PFXS) + str(random.randint(1, 254))

def _demo_packet():
    proto = _wrandom(_PROTOS, _PROTO_W)
    flags = _wrandom(_FLAGS, _FLAG_W) if proto in ("TCP","HTTP","HTTPS","TLS") else ""
    dport_map = {"HTTP":80,"HTTPS":443,"DNS":53,"TLS":443,"FTP":21,
                 "DHCP":67,"SNMP":161,"TELNET":23,"POP3":110}
    dst_port = dport_map.get(proto, random.choice(_WELL_PORTS) if random.random()<0.3
                             else random.randint(1024, 65535))
    query = None
    if proto == "DNS":
        domains = ["google.com","cloudflare.com","github.com","api.example.com",
                   "windowsupdate.com","discord.com"]
        query = random.choice(domains).encode()
    pkt = PyPacket(
        src_mac   =":".join(f"{random.randint(0,255):02x}" for _ in range(6)),
        dst_mac   =":".join(f"{random.randint(0,255):02x}" for _ in range(6)),
        protocol  = proto,
        type      = 8 if proto=="ICMP" else None,
        src_ip    = _rand_ip(),
        dst_ip    = _rand_ip(public=True),
        src_port  = random.randint(1024, 65535),
        dst_port  = dst_port,
        flags     = flags or None,
        query     = query,
        timestamp = time.time(),
    )
    return pkt

'''
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

    def __init__(self, device_path: str = "", parent=None):
        super().__init__(parent)
        self.device_path  = device_path
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
        sweep_q  = queue.Queue()
        arp_q    = queue.Queue()
        dns_q    = queue.Queue()
        ready    = threading.Event(); ready.set()

        def _capture():
            from capture.capture import begin_capture
            begin_capture(
                self.device_path.encode(),
                [cli_q, fast_q, slow_q, arp_q],
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
            detect_port_scan(fast_q, 10, 20, 30, self.stop_event, ready, alert_callback=_emit_alert)
        def _slow_scan():
            detect_port_scan(slow_q, 60, 50, 30, self.stop_event, ready, alert_callback=_emit_alert)
        def _sweep():
            detect_sweep(sweep_q, 5, 10, 300, self.stop_event, ready)
        def _arp():
            detect_arp_spoof(arp_q, 30, self.stop_event, ready, alert_callback=_emit_alert)
        def _dns():
            detect_dns_tunnel(dns_q, self.stop_event, ready, alert_callback=_emit_alert)

        targets = [_capture, lambda: _drain(cli_q), _fast_scan, _slow_scan, _arp]
        for fn in targets:
            t = threading.Thread(target=fn, daemon=True)
            t.start()
            self._threads.append(t)

    '''# ── Demo capture ───────────────────────────────────────────────────────────
    def _start_demo(self):
        def _demo_loop():
            while not self.stop_event.is_set():
                burst = random.randint(1, 8)
                for _ in range(burst):
                    pkt = _demo_packet()
                    self._on_packet(pkt)
                time.sleep(0.15)

        def _demo_alerts():
            _ALERT_TEMPLATES = [
                ("critical", "PORT SCAN DETECTED",
                 "SYN scan across {n} ports from {ip}"),
                ("critical", "SYN FLOOD",
                 "Excessive SYN packets from {ip} — {n} in 10s"),
                ("warning",  "ICMP SWEEP",
                 "Ping sweep across subnet from {ip}"),
                ("critical", "ARP SPOOFING",
                 "MAC address changed for known IP {ip}"),
                ("warning",  "DNS TUNNELING",
                 "High-entropy domain queried from {ip} (entropy=4.72)"),
                ("info",     "SLOW PORT SCAN",
                 "Low-rate stealth scan from {ip} over 60s window"),
                ("warning",  "XMAS SCAN",
                 "FIN+PSH+URG flags set simultaneously from {ip}"),
                ("info",     "NULL SCAN",
                 "No TCP flags — evasion attempt from {ip}"),
                ("warning",  "MAIMON SCAN",
                 "FIN+ACK probe from {ip}"),
            ]
            while not self.stop_event.is_set():
                delay = random.uniform(5, 14)
                time.sleep(delay)
                if self.stop_event.is_set():
                    break
                sev, title, tmpl = random.choice(_ALERT_TEMPLATES)
                ip = _rand_ip()
                body = tmpl.format(ip=ip, n=random.randint(20, 120))
                self.alert_fired.emit(sev, title, body)

        for fn in (_demo_loop, _demo_alerts):
            t = threading.Thread(target=fn, daemon=True)
            t.start()
            self._threads.append(t)'''

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
