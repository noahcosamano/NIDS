from capture.classes.PyPacket import PyPacket
from network.block_ip import block_ip, unblock_ip
from network.get_gateway import get_gateway
from network.get_ip import get_ip
from detect.config import flag_to_name
from log.log import report_to_webhook
import time

class PortScan:
    def __init__(self, device, packet_queue, interval, quantity, cooldown, alert_callback=None):
        self.packet_queue = packet_queue
        self.interval = interval
        self.quantity = quantity
        self.cooldown = cooldown
        self.gateway = get_gateway()
        self.host_ip = get_ip(device)
        self.last_alert = {}   # src_ip -> {flag: last_alert_time}
        self.activity = {}     # src_ip -> list of (timestamp, dst_port)
        self.num_flags = {}    # src_ip -> {flag: count}
        self.alert_callback = alert_callback

    def process_packet(self, packet: PyPacket):
        now = packet.timestamp
        src_ip = packet.src_ip
        dst_port = packet.dst_port
        flags = packet.flags or "NONE"

        if not src_ip or not dst_port:
            return

        if (self.gateway and src_ip == self.gateway) or src_ip.startswith("128."):
            return

        if dst_port >= 1024:
            return
        
        if self.host_ip and self.host_ip.replace("(Preferred)", "").strip() == src_ip:
            ...

        if src_ip not in self.activity:
            self.activity[src_ip]   = []
            self.num_flags[src_ip]  = {}
            self.last_alert[src_ip] = {}

        self.num_flags[src_ip][flags] = self.num_flags[src_ip].get(flags, 0) + 1
        self.activity[src_ip].append((now, dst_port))

        cutoff = now - self.interval
        self.activity[src_ip] = [(t, p) for t, p in self.activity[src_ip] if t >= cutoff]

        self.check_scan(src_ip, now)

    def check_scan(self, src_ip, now):
        unique_ports = {p for _, p in self.activity[src_ip]}
        counts = self.num_flags.get(src_ip, {})

        for flag, num in list(counts.items()):
            if num < self.quantity or len(unique_ports) < self.quantity:
                continue

            last_time = self.last_alert[src_ip].get(flag, 0)
            if now - last_time < self.cooldown:
                continue

            # Record alert time for this specific flag
            self.last_alert[src_ip][flag] = now

            # Clear ALL flag counts — packets seen during one scan type
            # will have inflated counts for every other type too, so leaving
            # them causes cascade false positives on the very next packet.
            # Per-flag cooldowns above ensure each type can still re-detect
            # independently once the cooldown expires.
            self.num_flags[src_ip].clear()

            self.log_alert(src_ip, flag)
            return  # one alert per packet is enough; recheck next packet

    def log_alert(self, src_ip, flag):
        scan_type = flag_to_name.get(flag, flag)
        message = f"\n{time.ctime()}\n{scan_type}\nSource IP: {src_ip}\n"

        for t, p in sorted(self.activity[src_ip], key=lambda x: x[1]):
            message += f"{time.ctime(t)} | Port: {p}\n"

        message += f"Blocking {src_ip} for 300 seconds\n"
        report_to_webhook(scan_type, message)

        if self.alert_callback:
            unique_ports = len({p for _, p in self.activity.get(src_ip, [])})
            self.alert_callback(
                "critical",
                scan_type.upper() if scan_type else "unknown scan",
                f"{scan_type} across {unique_ports} ports from {src_ip}"
            )

        cutoff = time.time() - self.interval
        self.activity[src_ip] = [(t, p) for t, p in self.activity[src_ip] if t >= cutoff]


def detect_port_scan(device, packet_queue, interval, quantity, cooldown, stop_event, cli_ready, alert_callback=None):
    detector = PortScan(device, packet_queue, interval, quantity, cooldown, alert_callback=alert_callback)

    while not stop_event.is_set() and cli_ready.is_set():
        unblock_ip()
        packet: PyPacket = packet_queue.get()
        try:
            detector.process_packet(packet)
        finally:
            packet_queue.task_done()