from utils.ui_helpers import clear, error
import ipaddress
import re
from datetime import datetime, timezone, timedelta
from database.query import query

valid_filters = ("-n", "-ip", "-severity", "-detector", "-since", "-date")
valid_severity = ("info", "warning", "medium", "high", "critical")
valid_detectors = ("arp-spoof", "dns-tunnel", "port-scan", "honeyport")

TIME_MULTIPLIERS = {
    "h": 3600,
    "m": 60,
    "s": 1,
}

def execute(command: str):
    #input("DEBUG: Execute called")
    command = command.lower()
    
    filters = {
        "n": None,
        "ip": None,
        "mac": None,
        "port": None,
        "severity": None,
        "detector": None,
        "since": None,
        "date": None
    }
    
    tokens = parse_command(command)
    #input(f"DEBUG: Command parsed | Length: {len(tokens)}")
    
    if len(tokens) > 1:
        for token in tokens[1:]:
            if not parse_filter(token, filters):
                #input("DEBUG: Command invalid — stopping")
                return
        
    pass_filters(filters)
    
def parse_filter(token: str, filters):
    #input("DEBUG: Parsing filter")
    
    parts = token.split("=")
    #input(f"DEBUG: filter: {parts[0]}")
    if parts[0] == "help":
        help()
        return False
    elif parts[0] not in valid_filters:
        clear()
        error(f"'{parts[0]}' is not a valid filter")
        return False
    elif len(parts) == 1:
        clear()
        error(f"'{parts[0]} is missing a value")
        return False
    elif len(parts) > 2:
        clear()
        error(f"'{parts[0]} only takes one argument")
        return False
        
    filter, value = parts[0], parts[1]
    
    #input(f"DEBUG: value: {parts[1]}")
    
    if filter == "-n":
        if parse_number(value) is False:
            clear()
            error("value must be a positive integer. Use 'history help' for more information")
            return False
        filters["n"] = value
    if filter == "-ip":
        if parse_ip(value) is False:
            clear()
            error("invalid ip address. Use 'history help' for more information")
            return False
        filters["ip"] = value
    if filter == "-mac":
        if parse_mac(value) is False:
            clear()
            error("invalid mac address. Use 'history help' for more information")
            return False
        filters["mac"] = value
    if filter == "-port":
        if parse_port(value) is False:
            clear()
            error("invalid port. Use 'history help' for more information")
            return False
        filters["port"] = value
    if filter == "-severity":
        if parse_severity(value) is False:
            clear()
            error("invalid severity value. Use 'history help' for more information")
            return False
        filters["severity"] = value
    if filter == "-detector":
        if parse_detector(value) is False:
            clear()
            error("invalid detector value. Use 'history help' for more information")
            return False
        filters["detector"] = value
    if filter == "-since":
        total_seconds = parse_since(value)
        if total_seconds is None or total_seconds == 0:
            clear()
            error("invalid time value. Use 'history help' for more information")
            return False
        filters["since"] = total_seconds
    if filter == "-date":
        date = parse_date(value)
        if date is None:
            clear()
            error("invalid date value. Use 'history help' for more information")
            return False
        filters["date"] = date
        
    return True
        
def parse_number(number):
    try:
        return int(number) > 0
    except ValueError:
        return False

def parse_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
    
def parse_mac(mac):
    mac = mac.strip()

    # Colon-separated or hyphen-separated
    pattern1 = r'^([0-9a-f]{2}[:-]){5}([0-9a-f]{2})$'
    # Dot-separated (Cisco style)
    pattern2 = r'^([0-9a-f]{4}\.){2}([0-9a-f]{4})$'

    if re.fullmatch(pattern1, mac) or re.fullmatch(pattern2, mac):
        return True
    return False

def parse_port(port):
    try:
        return 0 <= int(port) <= 65535
    except ValueError:
        return False
    
def parse_severity(severity):
    return severity in valid_severity

def parse_detector(detector):
    return detector in valid_detectors

def parse_since(time: str):
    pattern = r"(\d+)([hms])"
    matches = re.findall(pattern, time)
    
    if not matches:
        return None
    
    total_seconds = 0
    
    for amount, unit in matches:
        total_seconds += int(amount) * TIME_MULTIPLIERS[unit]

    if total_seconds == 0:
        return None
    return f"-{total_seconds} seconds"

def parse_date(date: str):
    """
    Convert a local-date string like '2026-04-07' into a (start_utc, end_utc)
    tuple representing midnight to midnight in the user's local timezone,
    expressed as UTC strings for the database.
    """
    try:
        local_midnight = datetime.strptime(date, "%Y-%m-%d").astimezone()
    except ValueError:
        return None

    next_local_midnight = local_midnight + timedelta(days=1)

    start_utc = local_midnight.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    end_utc = next_local_midnight.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    return (start_utc, end_utc)
    
def parse_command(command: str):
    #input(f"DEBUG: Parsing {command}")
    command = command.split()
    #input(f"DEBUG: Parsed: {command}")
    return command

def help():
    clear()

    print(" " + "═"*85)
    print("  HISTORY COMMAND HELP")
    print(" " + "═"*85)

    print("\n\033[1mUSAGE:\033[0m")
    print("  history [filters]\n")

    print("\033[1mFILTERS:\033[0m")

    print("\n  \033[94m-n=N\033[0m")
    print("  └─ Limit number of results returned.")
    print("     Example: history -n=25")

    print("\n  \033[94m-ip=ADDR\033[0m")
    print("  └─ Filter detections by IPv4 or IPv6 address.")
    print("     Example: history -ip=192.168.1.10")

    print("\n  \033[94m-mac=ADDR\033[0m")
    print("  └─ Filter detections by MAC address.")
    print("     Valid formats:")
    print("       - Colon-separated: AA:BB:CC:DD:EE:FF")
    print("       - Hyphen-separated: AA-BB-CC-DD-EE-FF")
    print("       - Cisco-style dot-separated: AABB.CCDD.EEFF")
    print("     Example: history -mac=00:1A:2B:3C:4D:5E")

    print("\n  \033[94m-port=NUM\033[0m")
    print("  └─ Filter detections by port number (0-65535).")
    print("     Example: history -port=443")

    print("\n  \033[94m-severity=LEVEL\033[0m")
    print("  └─ Filter by alert severity.")
    print(f"     Valid values: {', '.join(valid_severity)}")
    print("     Example: history -severity=high")

    print("\n  \033[94m-detector=TYPE\033[0m")
    print("  └─ Filter by detection module.")
    print(f"     Valid values: {', '.join(valid_detectors)}")
    print("     Example: history -detector=port-scan")

    print("\n  \033[94m-since=TIME\033[0m")
    print("  └─ Show alerts within a relative time window.")
    print("     Format: <number>[h|m|s]")
    print("     Examples:")
    print("       history -since=1h")
    print("       history -since=30m")
    print("       history -since=10m30s")

    print("\n  \033[94m-date=YYYY-MM-DD\033[0m")
    print("  └─ Show alerts from a specific date.")
    print("     Example: history -date=2026-04-07")

    print("\n\033[1mEXAMPLES:\033[0m")
    print("  history -n=10")
    print("  history -severity=critical")
    print("  history -ip=10.0.0.5 -since=2h")
    print("  history -detector=arp-spoof -date=2026-04-01")
    print("  history -mac=00:1A:2B:3C:4D:5E")
    print("  history -port=443")

    print("\n" + "─"*87)
    input("\nPress ENTER to return...")
    clear()

# Query database after command has been returned from execute if command is valid
def pass_filters(filters: dict):
    n = filters.get("n")
    ip = filters.get("ip")
    mac = filters.get("mac")
    port = filters.get("port")
    severity = filters.get("severity")
    detector = filters.get("detector")
    since = filters.get("since")
    date = filters.get("date")
    
    if detector == "honeyport":
        detector = "Honey Port"
    elif detector == "arp-spoof":
        detector = "ARP Spoof"
    elif detector == "dns-tunnel":
        detector = "DNS Tunnel"
    elif detector == "port-scan":
        detector = "Port Scan"
    
    rows = query(n, ip, mac, port, severity, detector, since, date)
    print_results(rows)
    
def format_timestamp(utc_str):
    """Convert a SQLite UTC timestamp string to local time for display."""
    if not utc_str:
        return ''
    # SQLite stores as 'YYYY-MM-DD HH:MM:SS' with no timezone info,
    # but datetime('now') always produces UTC
    dt_utc = datetime.strptime(utc_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    dt_local = dt_utc.astimezone()  # converts to system local time
    return dt_local.strftime("%Y-%m-%d %H:%M:%S")
    
def print_results(rows):
    if not rows:
        print("\nNo detections found.\n")
        input("Press ENTER to return...")
        clear()
        return

    print(f"\n  Found {len(rows)} detection(s):\n")
    print(f"  {'TIME':<20} {'SEVERITY':<10} {'DETECTOR':<14} {'SRC':<18} {'DST':<18} SUMMARY")
    print("  " + "─" * 110)

    for row in rows:
        ts = format_timestamp(row['timestamp'])
        sev = (row['severity'] or '')[:10]
        det = (row['detector_type'] or '')[:14]
        src = f"{row['src_ip'] or '-'}:{row['src_port'] or ''}"[:18]
        dst = f"{row['dst_ip'] or '-'}:{row['dst_port'] or ''}"[:18]
        summary = (row['summary'] or '')[:60]
        print(f"  {ts:<20} {sev:<10} {det:<14} {src:<18} {dst:<18} {summary}")

    print()
    input("Press ENTER to return...")
    clear()