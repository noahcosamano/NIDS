from cli.verify import verify_target
from cli.commands import view, devices, stats
from utils.ui_helpers import error

def parse_wait(parts):
    # Get "wait" argument, this is so terminal does not get clogged with many packets
    wait_ms = 0

    for part in parts:
        if part.startswith("-wait="):
            # Usual format is "-wait=100"
            value = part.split("=", 1)[1]

            if not value.isdigit():
                raise ValueError("wait must be an integer")

            wait_ms = int(value)
        else:
            # Any argument other than "wait" is invalid
            raise ValueError("unknown argument provided")

    return wait_ms

# Command helper
def parse_command(packet_queue, cmd: str, stop_event):
    parts = cmd.strip().split() # Splits command on spaces and puts each token in a list

    if not parts:
        raise ValueError("empty command")

    command = parts[0].lower() # Main command e.g. 'view', 'devices', etc.

    if command == "view": # Filter and view protocol
        if len(parts) < 2:
            error("'view' requires a protocol or port")
        
        # ie. "tcp", "53", "arp"
        target = verify_target(parts[1])
        wait_ms = parse_wait(parts[2:])
        
        view.execute(packet_queue, target, wait_ms, stop_event)
        return
    
    if command == "devices": # View all network devices on computer
        if len(parts) > 1:
            error("'devices' takes no arguments")
            
        devices.execute(stop_event)
        return
    
    if command == "stats": # View network capture statistic such as packet loss
        if len(parts) > 1:
            error("'stats' takes no arguments")
            
        stats.execute(stop_event)
        return
    
    error("Invalid command")