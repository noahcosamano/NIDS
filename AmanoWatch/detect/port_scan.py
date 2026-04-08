from capture.classes.PyPacket import PyPacket
from network.block_ip import block_ip, unblock_ip
from network.get_gateway import get_gateway
from network.get_ip import get_ip
from detect.config import FLAG_TO_NAME
from database.edit import add_detection
from collections import deque, defaultdict
import time
import traceback


class _SourceState:
    """
    Per-source tracking state. One of these exists per src_ip.

    For each scan type we maintain:
      - window:       deque of (timestamp, port) ordered by time
      - port_counts:  dict of {port: occurrences_in_window} — lets us know
                      when a port leaves the window entirely so we can
                      shrink the unique-port set incrementally
      - last_alert:   last time we alerted on this scan type
    """
    __slots__ = ("windows", "port_counts", "last_alert")

    def __init__(self):
        self.windows     = defaultdict(deque)            # scan_type -> deque[(ts, port)]
        self.port_counts = defaultdict(lambda: defaultdict(int))  # scan_type -> {port: count}
        self.last_alert  = {}                            # scan_type -> ts


class PortScan:
    def __init__(self, device, packet_queue, interval, quantity, cooldown, alert_callback=None):
        self.packet_queue = packet_queue
        self.interval = interval
        self.quantity = quantity
        self.cooldown = cooldown
        self.gateway = get_gateway()
        self.host_ip = get_ip(device)
        self.alert_callback = alert_callback
        self.sources = {}   # src_ip -> _SourceState

        if self.host_ip:
            self.host_ip = self.host_ip.replace("(Preferred)", "").strip()

    def process_packet(self, packet: PyPacket):
        src_ip = packet.src_ip
        dst_port = packet.dst_port
        flags = packet.flags or "NONE"

        if not src_ip or not dst_port:
            return

        # NOTE: "128." is a temporary loopback-testing hack — change back to "127."
        if (self.gateway and src_ip == self.gateway) or src_ip.startswith("128."):
            return

        # Ignore our own outbound traffic so replies don't get counted as scans
        if self.host_ip and self.host_ip == src_ip:
            return

        # Only count flag combinations that match a known probe type.
        # Normal mid-stream traffic (ACK, PSH ACK, etc.) drops out here,
        # which eliminates >95% of packets before any expensive work.
        scan_type = FLAG_TO_NAME.get(flags)
        if scan_type is None:
            return

        now = packet.timestamp

        # Lazy-create per-source state
        state = self.sources.get(src_ip)
        if state is None:
            state = _SourceState()
            self.sources[src_ip] = state

        window = state.windows[scan_type]
        port_counts = state.port_counts[scan_type]

        # Evict expired entries from the front of the deque. O(k) where k
        # is the number of entries that actually expired this tick — usually
        # 0 or 1, not the whole window.
        cutoff = now - self.interval
        while window and window[0][0] < cutoff:
            _, old_port = window.popleft()
            port_counts[old_port] -= 1
            if port_counts[old_port] <= 0:
                del port_counts[old_port]

        # Record the new probe
        window.append((now, dst_port))
        port_counts[dst_port] += 1

        # Fast reject: len(port_counts) is the unique-port count, maintained
        # incrementally. If we're below threshold, bail immediately — no need
        # to even call check_scan.
        if len(window) < self.quantity or len(port_counts) < self.quantity:
            return

        # Cooldown check
        last_time = state.last_alert.get(scan_type, 0)
        if now - last_time < self.cooldown:
            return
        state.last_alert[scan_type] = now

        self._log_alert(packet, scan_type, window, port_counts)

        # Reset this scan type's window so we don't re-alert on the same burst
        window.clear()
        port_counts.clear()

    def _log_alert(self, packet: PyPacket, scan_type: str, window, port_counts):
        src_ip = packet.src_ip
        unique_ports = len(port_counts)

        # Only format the full packet list for the DB — not the hot path
        all_packets = ""
        for t, p in sorted(window, key=lambda x: x[1]):
            all_packets += f"{time.ctime(t)} | Port: {p}\n"

        summary = f"{src_ip} performed {scan_type} across {unique_ports}+ ports in {self.interval}s"
        details = f"Scan type: {scan_type}\nUnique ports: {unique_ports}\nPackets:\n{all_packets}"

        add_detection(
            detector_type="Port Scan",
            severity="warning",
            summary=summary,
            src_ip=src_ip,
            src_mac=packet.src_mac,
            src_port=packet.src_port,
            dst_ip=packet.dst_ip,
            dst_mac=packet.dst_mac,
            dst_port=packet.dst_port,
            details=details,
        )

        if self.alert_callback:
            self.alert_callback(
                "warning",
                scan_type.upper(),
                f"{scan_type} across {unique_ports} ports from {src_ip}"
            )


def detect_port_scan(device, packet_queue, interval, quantity, cooldown, stop_event, cli_ready, alert_callback=None):
    detector = PortScan(device, packet_queue, interval, quantity, cooldown, alert_callback=alert_callback)

    while not stop_event.is_set() and cli_ready.is_set():
        unblock_ip()
        packet: PyPacket = packet_queue.get()
        try:
            detector.process_packet(packet)
        except Exception as e:
            print(f"[ERROR] port_scan: {e!r}")
            traceback.print_exc()
        finally:
            packet_queue.task_done()