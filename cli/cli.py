from queue import Queue
import threading
from view_packets import view_proto, view_port
from logs.log import add_to_log
import os

VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "IGMP", "ALL"}


# -------------------------
# UI HELPERS
# -------------------------
def clear():
    os.system("cls")


def error(msg: str):
    clear()
    print(f" Error: {msg}")


def welcome():
    print("\n=== NIDS CLI ===")
    print("Commands:")
    print("  view [protocol | port] -wait=[milliseconds]")
    print("    example: view tcp -wait=500")
    print("    example: view 80 -wait=500")
    print("  exit\n")


# -------------------------
# VALIDATION
# -------------------------
def validate_target(arg: str):
    """Validate protocol or port."""
    arg = arg.upper()

    if arg in VALID_PROTOCOLS:
        return arg

    if arg.isdigit():
        port = int(arg)
        if 1 <= port <= 65535:
            return port

    raise ValueError(f"'{arg}' is not a valid protocol or port")


def parse_wait(parts):
    """Extract -wait argument."""
    wait_ms = 0

    for part in parts:
        if part.startswith("-wait="):
            value = part.split("=", 1)[1]

            if not value.isdigit():
                raise ValueError("wait must be an integer")

            wait_ms = int(value)
        else:
            raise ValueError("unknown argument provided")

    return wait_ms


# -------------------------
# COMMAND PARSER
# -------------------------
def parse_command(cmd: str):
    parts = cmd.strip().split()

    if not parts:
        raise ValueError("empty command")

    command = parts[0].lower()

    if command != "view":
        raise ValueError(f"'{command}' is not a valid command")

    if len(parts) < 2:
        raise ValueError("'view' requires a protocol or port")

    target = validate_target(parts[1])
    wait_ms = parse_wait(parts[2:])

    return {
        "command": "view",
        "target": target,
        "wait_ms": wait_ms,
    }


# -------------------------
# CLI LOOP
# -------------------------
def start_cli(packet_queue: Queue):
    stop_event = None
    worker_thread = None

    while True:
        welcome()
        cmd = input("NIDS> ")
        add_to_log(f"{cmd}\n", "command_log.txt")

        if cmd.lower() == "exit":
            print("Exiting CLI...")
            if stop_event:
                stop_event.set()
            if worker_thread:
                worker_thread.join()
            break

        try:
            parsed = parse_command(cmd)
        except ValueError as e:
            error(str(e))
            continue

        # stop previous listener
        if stop_event:
            stop_event.set()
        if worker_thread:
            worker_thread.join()

        stop_event = threading.Event()

        target = parsed["target"]
        wait_ms = parsed["wait_ms"]

        if isinstance(target, str):
            clear()
            print(f"\nListening for {target} packets (delay={wait_ms}ms)...")
            view_proto(packet_queue, target, stop_event, wait_ms)
        else:
            clear()
            print(f"\nListening on port {target} (delay={wait_ms}ms)...")
            view_port(packet_queue, target, stop_event, wait_ms)