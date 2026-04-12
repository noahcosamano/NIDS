from capture.classes.PyPacket import PyPacket
from detect.config import DNS_WHITELIST
from database.edit import add_detection
import math
import time
from queue import Queue
from threading import Event
from collections import Counter


class _SourceState:
    def __init__(self, ip):
        self.ip = ip
        self.entries = []   # list of dicts: {packet, subdomain_len, entropy, timestamp}
        self.risk = 0.0

    def add(self, packet: PyPacket, subdomain_len: int, entropy: float):
        self.entries.append({
            "packet": packet,
            "subdomain_len": subdomain_len,
            "entropy": entropy,
            "timestamp": packet.timestamp,
        })

    def clean(self, interval: int):
        cutoff = time.time() - interval
        self.entries = [e for e in self.entries if e["timestamp"] >= cutoff] # Clears entries of packets not in time frame anymore

    @property
    def packet_count(self) -> int:
        return len(self.entries)

    def calculate_risk(self):
        """
        Example:
            Subdomain Length: 100
            Entropy: 2.0
            Packets: 20
                len_score = 8
                ent_score = 2
                peak = 10
                suspicious count = 20
                volume bonus = 9.5
            risk = 19.5
            
            Subdomain Length: 160
            Entropy: 4.85
            Packets: 1
                len_score = 14
                ent_score = 4.85
                peak = 18.85
                suspicious count = 1
                volume bonus = 0
            risk = 18.85
        """
        if not self.entries:
            self.risk = 0.0
            return

        scores = [] # List of floats, each float is the score of each packet
        for e in self.entries: # Each entry is a packet and its corresponding subdomain/entropy
            len_score = max(0, (e["subdomain_len"] - 20) * 0.1) # Max so the score cannot be negative
            ent_score = e["entropy"]
            scores.append(len_score + ent_score)

        peak = max(scores)
        suspicious_count = sum(1 for s in scores if s >= 5.0) # Scores above 5 are considered suspiscious
        volume_bonus = max(0, (suspicious_count - 1) * 0.5) # Max so volume bonus cannot be negative, this tracks the amount of "bad packets"

        self.risk = peak + volume_bonus # Risk is a calculation of the worst packet, and the amount of "bad packets" put together

class DnsTunnel:
    def __init__(self, interval=60, cooldown=30, alert_callback=None):
        self.alert_callback = alert_callback
        self.interval = interval
        self.cooldown = cooldown
        self.activity = {}       # src_ip -> _SourceState
        self.last_alert = {}     # src_ip -> timestamp

    def process_packet(self, packet: PyPacket):
        if not packet.payload or not packet.src_ip:
            return

        domain = self._parse_dns_name(packet.payload)
        
        if not domain:
            return
        if domain.endswith(".local") or domain.endswith(".arpa"):
            return
        if any(domain.endswith(trusted) for trusted in DNS_WHITELIST):
            return

        subdomain = self._subdomain(domain)
        if not subdomain:
            return

        subdomain_no_dots = subdomain.replace(".", "")
        if not subdomain_no_dots:
            return

        sub_len = len(subdomain_no_dots)
        entropy = self._entropy(subdomain_no_dots)

        src = packet.src_ip
        state = self.activity.get(src)
        if state is None:
            state = _SourceState(src)
            self.activity[src] = state

        state.add(packet, sub_len, entropy)
        state.clean(self.interval)
        state.calculate_risk()

        severity = None
        if state.risk >= 8.0:
            severity = "critical"
        elif state.risk >= 6.5:
            severity = "high"
        elif state.risk >= 5.5:
            severity = "medium"
        else:
            return

        now = time.time()
        if now - self.last_alert.get(src, 0) < self.cooldown:
            return
        self.last_alert[src] = now

        self._detected(severity, packet, domain, sub_len, entropy, state)

    def _subdomain(self, domain: str) -> str:
        """Return everything left of the registered domain (last two labels)."""
        parts = domain.rstrip(".").split(".")
        if len(parts) <= 2:
            return ""
        return ".".join(parts[:-2])

    def _entropy(self, s: str) -> float:
        """Shannon entropy in bits per character."""
        if not s:
            return 0.0
        total = len(s)
        entropy = 0.0
        for count in Counter(s).values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    def _parse_dns_name(self, payload: bytes) -> str:
        """
        Extract the QNAME from a DNS question section.

        Packet layout: 12-byte DNS header, then the QNAME as a sequence of
        length-prefixed labels terminated by a zero byte.
        """
        if not payload or len(payload) < 13:
            return ""

        try:
            parts = []
            i = 12
            max_iterations = 128

            while i < len(payload) and max_iterations > 0:
                max_iterations -= 1
                length = payload[i]

                if length == 0:
                    break
                if length > 63:
                    return ""
                if i + 1 + length > len(payload):
                    return ""

                label = payload[i + 1 : i + 1 + length]
                try:
                    decoded = label.decode("ascii")
                except UnicodeDecodeError:
                    return ""
                if not all(32 <= b < 127 for b in label):
                    return ""

                parts.append(decoded)
                i += 1 + length

            return ".".join(parts)
        except Exception as e:
            return ""

    def _detected(self, severity: str, packet: PyPacket, domain: str,
                  sub_len: int, entropy: float, state: _SourceState):
        summary = (
            f"{packet.src_ip} queried suspicious domain "
            f"(possible DNS tunnel, risk {state.risk:.2f})"
        )

        details = (
            f"Source: {packet.src_ip}\n"
            f"Triggering domain: {domain[:100]}\n"
            f"Subdomain length: {sub_len}\n"
            f"Entropy: {entropy:.2f} bits\n"
            f"Risk score: {state.risk:.2f}\n"
            f"Queries in window: {state.packet_count}\n"
            f"Recent queries:\n"
        )
        for entry in state.entries[-10:]:
            p: PyPacket = entry["packet"]
            q_domain = self._parse_dns_name(p.payload) if p.payload else "?"
            details += (
                f"  {time.ctime(entry['timestamp'])} | "
                f"len={entry['subdomain_len']} | "
                f"ent={entry['entropy']:.2f} | "
                f"{q_domain[:80]}\n"
            )

        if self.alert_callback:
            self.alert_callback(
                severity,
                "DNS TUNNELING",
                f"High-entropy domain from {packet.src_ip}: {domain[:80]}"
            )

        add_detection(
            detector_type="DNS Tunnel",
            severity=severity,
            summary=summary,
            src_ip=packet.src_ip,
            src_mac=packet.src_mac,
            src_port=packet.src_port,
            dst_ip=packet.dst_ip,
            dst_mac=packet.dst_mac,
            dst_port=packet.dst_port,
            details=details,
        )


def detect_dns_tunnel(packet_queue: Queue, stop_event: Event, cli_ready: Event, alert_callback=None):
    detector = DnsTunnel(alert_callback=alert_callback)

    while not stop_event.is_set() and cli_ready.is_set():
        packet = packet_queue.get()
        try:
            detector.process_packet(packet)
        finally:
            packet_queue.task_done()