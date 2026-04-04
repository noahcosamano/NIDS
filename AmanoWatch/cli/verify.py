from capture.config.config import protocol_nums, tcp_service_ports, udp_service_ports

def verify_target(arg: str):
    """Validates protocol or port."""
    arg = arg.upper()

    # Checks if argument passed in is valid against all protocols used
    if arg in protocol_nums.values() or arg == "ALL" or arg in tcp_service_ports.values() or arg in udp_service_ports.values():
        return arg

    if arg.isdigit():
        port = int(arg)
        if 1 <= port <= 65535: # 1 - 65535 is range of valid ports
            return port

    # Arg must either be protocol or port, I intend on adding IP filtering and multifiltering
    raise ValueError(f"'{arg}' is not a supported protocol or port")