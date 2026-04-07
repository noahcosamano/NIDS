from detect.config import HONEY_PORTS
from capture.classes.PyPacket import PyPacket
from log.log import report_to_webhook
from network.block_ip import block_ip, unblock_ip
from network.get_gateway import get_gateway
from network.get_ip import get_ip
from utils.geolocate_ip import search_ip

class HoneyPort:
    def __init__(self, device, packet_queue, alert_callback=None):
        self.packet_queue = packet_queue
        self.alert_callback = alert_callback
        self.gateway = get_gateway()
        self.host_ip = get_ip(device).replace("(Preferred)","").strip()
    
        print(f"Device: {device} | Host IP: {self.host_ip}")
        
    def _process_packet(self, packet: PyPacket):
        now = packet.timestamp
        dst_port = packet.dst_port
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        
        #print(f"Time: {now} | Port: {dst_port} | IP: {src_ip}")
        
        if not src_ip or not dst_port or not dst_ip:
            return
        
        if dst_ip != self.host_ip:
            return
        
        if src_ip == self.host_ip or src_ip == self.gateway or src_ip.startswith("127."):
            return
        
        protocol, reason = self.check_port(dst_port)
        
        if protocol and reason:
            self.detect(now, src_ip, dst_port, protocol, reason)
        
    def check_port(self, dst_port):
        if dst_port in HONEY_PORTS.keys():
            protocol = HONEY_PORTS[dst_port].get("protocol")
            reason = HONEY_PORTS[dst_port].get("reason")
            
            #print(f"Protocol: {protocol} | Reason: {reason}")
            
            return protocol, reason
        
        return None, None
    
    def detect(self, timestamp, src_ip, dst_port, protocol, reason):
        #block_ip(src_ip)
        country = search_ip(src_ip) or "Unknown"
        message = f"\n{timestamp}\nHoneyport Traffic\nSource IP: {src_ip} ({country})\n"
        message += f"Traffic on port {dst_port} detected.\n"
        message += f"{dst_port} is usually used for {protocol}.\n"
        message += f"Reason for detection: {reason}\n"
        message += f"Blocking {src_ip} for 300 seconds"
        report_to_webhook("Honeyport Traffic", message)
        
        if self.alert_callback:
            self.alert_callback(
                "info",
                "Honeyport Connection Established",
                f"{src_ip} (origin: {country}) connected to port {dst_port}\nport {dst_port} is generally used for {protocol}" \
                    f"\nReason for alert: {reason}"
            )
        
def detect_honey_port_connection(device_name, packet_queue, stop_event, cli_ready, alert_callback=None):
    detector = HoneyPort(device_name, packet_queue, alert_callback=alert_callback)
    
    while not stop_event.is_set() and cli_ready.is_set():
        unblock_ip()
        packet: PyPacket = packet_queue.get()
        try:
            detector._process_packet(packet)
        finally:
            packet_queue.task_done()