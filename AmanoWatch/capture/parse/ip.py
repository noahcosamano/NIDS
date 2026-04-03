import socket

def format_ip(ip_array, is_ipv6):
    # Converts raw bytes from the c packet struct into a readable IP string
    try:
        if is_ipv6: # So the program knows when a packet is IPv6 format
            return socket.inet_ntop(socket.AF_INET6, bytes(ip_array))
        else:
            # IPv4 only uses the first 4 bytes of the 16-byte array
            return socket.inet_ntop(socket.AF_INET, bytes(ip_array[:4]))
    except Exception:
        return "Unknown"