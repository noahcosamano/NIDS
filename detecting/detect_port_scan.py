from configurations.packet import Packet
from utilities.block import block_ip, unblock_ip
from utilities.gateway import get_gateway
from configurations.scan_types import flag_to_name
from logs.log import add_to_log
import time

class PortScan:
    def __init__(self, packet_queue, interval, quantity, cooldown):
        self.packet_queue = packet_queue
        self.interval = interval          # seconds to track packets
        self.quantity = quantity          # unique ports threshold
        self.cooldown = cooldown          # cooldown before alerting same IP
        self.gateway = get_gateway()
        self.last_alert = {}              # src_ip -> last alert time
        self.activity = {}                # src_ip -> list of (timestamp, dst_port, flags)

    def process_packet(self, packet: Packet):
        """Process a single packet for scan detection."""
        now = packet.timestamp
        src_ip = packet.src_ip
        dst_port = packet.dst_port
        flags = packet.flags
        
        if not flags:
            flags = "NONE"

        if not src_ip or not dst_port:
            return

        # Skip gateway and loopback
        if (self.gateway and src_ip == self.gateway) or src_ip.startswith("128."):
            return
        
        if dst_port >= 1024:
            return

        # Track activity
        if src_ip not in self.activity:
            self.activity[src_ip] = []
            num_flags = self.filter_flags(dict(), flags)
        else:
            num_flags = self.filter_flags(self.activity[src_ip][0][2], flags)
            
        self.activity[src_ip].append((now, dst_port, num_flags))

        # Remove old packets outside interval
        cutoff = now - self.interval
        self.activity[src_ip] = [
            (t, p, f) for (t, p, f) in self.activity[src_ip] if t >= cutoff
        ]

        # Check for scan
        self.check_scan(src_ip, now)
        
    def filter_flags(self, num_flags: dict, flags: str):
        if not flags:
            return num_flags
        elif flags not in num_flags:
            num_flags[flags] = 1
        else:
            num_flags[flags] += 1
            
        return num_flags

    def check_scan(self, src_ip, now):
        """Check if a given IP has performed a port scan."""
        unique_ports = {p for _, p, _ in self.activity[src_ip]}
        num_flags: dict = self.activity[src_ip][0][2]

        for flag, num in num_flags.items():
            if num >= self.quantity and len(unique_ports) >= self.quantity:
                last_time = self.last_alert.get(src_ip, 0)
                if now - last_time < self.cooldown:
                    return

                self.last_alert[src_ip] = now
                self.log_alert(src_ip, flag)

                # Optionally block
                # block_ip(src_ip)

    def log_alert(self, src_ip, flag):
        """Log all activity of the IP neatly, sorted by port."""
        scan_type = flag_to_name[flag]
        message = f"\n{time.ctime()}\n{scan_type}\nSource IP: {src_ip}\n"
        sorted_activity = sorted(self.activity[src_ip], key=lambda x: x[1])  # sort by port

        for t, p, f in sorted_activity:
            message += f"{time.ctime(t)} | Port: {p} | Flags: {f}\n"

        message += f"Blocking {src_ip} for 300 seconds\n" + "-"*50
        add_to_log(message, "logs/detection_log.txt")

        # Keep activity so future packets can still be tracked
        # Remove only old packets outside interval
        cutoff = time.time() - self.interval
        self.activity[src_ip] = [
            (t, p, f) for (t, p, f) in self.activity[src_ip] if t >= cutoff
        ]

def detect_port_scan(packet_queue, interval, quantity, cooldown):
    """Thread entry point for scan detection."""
    detector = PortScan(packet_queue, interval, quantity, cooldown)

    while True:
        unblock_ip()  # unblock IPs periodically
        packet: Packet = packet_queue.get()
        try:
            detector.process_packet(packet)
        finally:
            packet_queue.task_done()