from capture.classes.PyPacket import PyPacket
from network.block_ip import block_ip, unblock_ip
from network.get_gateway import get_gateway
from network.get_ip import get_ip
from detect.config import FLAG_TO_NAME
from database.add_detection import add_detection
import time
import traceback


class PortScan:
    def __init__(self, device, packet_queue, interval, quantity, cooldown, alert_callback=None):
        self.packet_queue = packet_queue
        self.interval = interval
        self.quantity = quantity
        self.cooldown = cooldown
        self.gateway = get_gateway()
        self.host_ip = get_ip(device)
        self.last_alert = {}    # src_ip -> {scan_type: last_alert_time}
        self.activity = {}      # src_ip -> list of (timestamp, port, scan_type)
        self.scan_counts = {}   # src_ip -> {scan_type: count}
        self.alert_callback = alert_callback

        if self.host_ip:
            self.host_ip = self.host_ip.replace("(Preferred)", "").strip()

    def process_packet(self, packet: PyPacket):
        now = packet.timestamp
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

        # Only count packets whose flag combination matches a known scan type.
        # FLAG_TO_NAME contains exactly the probe combinations we care about
        # (SYN, FIN, FIN PSH URG, etc.) — anything else (RST ACK, PSH ACK,
        # SYN ACK, etc.) is reply/normal traffic and gets dropped here.
        scan_type = FLAG_TO_NAME.get(flags)
        if scan_type is None:
            return

        # Initialize per-source tracking on first sighting
        if src_ip not in self.activity:
            self.activity[src_ip]    = []
            self.scan_counts[src_ip] = {}
            self.last_alert[src_ip]  = {}

        self.scan_counts[src_ip][scan_type] = self.scan_counts[src_ip].get(scan_type, 0) + 1
        self.activity[src_ip].append((now, dst_port, scan_type))

        # Slide the window
        cutoff = now - self.interval
        self.activity[src_ip] = [(t, p, s) for t, p, s in self.activity[src_ip] if t >= cutoff]

        self.check_scan(packet, now)

    def check_scan(self, packet: PyPacket, now):
        src_ip = packet.src_ip
        counts = self.scan_counts.get(src_ip, {})

        for scan_type, num in list(counts.items()):
            # Count unique ports hit by THIS scan type only — prevents a SYN
            # flood from inflating the port count that ACK scan detection sees,
            # which was causing duplicate alerts on a single nmap run.
            unique_ports = {p for _, p, s in self.activity[src_ip] if s == scan_type}

            if num < self.quantity or len(unique_ports) < self.quantity:
                continue

            last_time = self.last_alert[src_ip].get(scan_type, 0)
            if now - last_time < self.cooldown:
                continue

            self.last_alert[src_ip][scan_type] = now

            # Clear ALL scan counts. Probes from one scan type can inflate
            # counts for others; per-type cooldowns above let each scan
            # re-detect independently.
            self.scan_counts[src_ip].clear()

            self.log_alert(packet, scan_type)
            return  # one alert per packet

    def log_alert(self, packet: PyPacket, scan_type: str):
        src_ip = packet.src_ip

        # Only show packets that belong to THIS scan type in the details
        type_packets = [(t, p) for t, p, s in self.activity[src_ip] if s == scan_type]

        all_packets = ""
        for t, p in sorted(type_packets, key=lambda x: x[1]):
            all_packets += f"{time.ctime(t)} | Port: {p}\n"

        unique_ports = len({p for _, p in type_packets})
        summary = f"{src_ip} performed {scan_type} across {unique_ports}+ ports in {self.interval}s"
        details = f"Scan type: {scan_type}\nUnique ports: {unique_ports}\nPackets:\n{all_packets}"

        # Persist to database
        add_detection(
            detector_type="Port Scan",
            severity="WARNING",
            summary=summary,
            src_ip=src_ip,
            src_mac=packet.src_mac,
            src_port=packet.src_port,
            dst_ip=packet.dst_ip,
            dst_mac=packet.dst_mac,
            dst_port=packet.dst_port,
            details=details,
        )

        # GUI alert last
        if self.alert_callback:
            self.alert_callback(
                "warning",
                scan_type.upper(),
                f"{scan_type} across {unique_ports} ports from {src_ip}"
            )

        # Trim window
        cutoff = time.time() - self.interval
        self.activity[src_ip] = [(t, p, s) for t, p, s in self.activity[src_ip] if t >= cutoff]


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