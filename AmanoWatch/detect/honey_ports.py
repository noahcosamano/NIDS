from detect.config import HONEY_PORTS
from capture.classes.PyPacket import PyPacket
from log.log import report_to_webhook
from network.block_ip import block_ip, unblock_ip

class HoneyPort:
    def __init__(self, packet_queue, alert_callback=None):
        self.packet_queue = packet_queue
        self.alert_callback = alert_callback
        
    def _process_packet(self, packet: PyPacket):
        now = packet.timestamp
        dst_port = packet.dst_port
        src_ip = packet.src_ip
        
        if not src_ip or not dst_port:
            return
        
        protocol, reason = self.check_port(dst_port)
        
        if protocol and reason:
            self.detect(now, src_ip, dst_port, protocol, reason)
        
    def check_port(self, dst_port):
        if dst_port in HONEY_PORTS.keys():
            protocol = HONEY_PORTS[dst_port].get("protocol")
            reason = HONEY_PORTS[dst_port].get("reason")
            
            return protocol, reason
        
        return None, None
    
    def detect(self, timestamp, src_ip, dst_port, protocol, reason):
        #block_ip(src_ip)
        message = f"\n{timestamp}\nHoneyport Traffic\nSource IP: {src_ip}\n"
        message += f"Traffic on port {dst_port} detected.\n"
        message += f"{dst_port} is usually used for {protocol}.\n"
        message += f"Reason for detection: {reason}\n"
        message += f"Blocking {src_ip} for 300 seconds"
        report_to_webhook("Honeyport Traffic", message)
        
def detect_honey_port_connection(packet_queue, stop_event, cli_ready, alert_callback=None):
    detector = HoneyPort(packet_queue, alert_callback)
    
    while not stop_event.is_set() and cli_ready.is_set():
        unblock_ip()
        packet: PyPacket = packet_queue.get()
        try:
            detector._process_packet(packet)
        finally:
            packet_queue.task_done()