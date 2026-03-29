from queue import Queue
import threading
from cli.view_packets import view_proto, view_port
from utilities.log import add_to_log, log_event
import os

# AmanoWatch currently supports these protocols
VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "ARP", "DNS", "IGMP", "ALL"}


# UI helpers
def clear():
    os.system("cls")


def error(msg: str):
    clear()
    print(f" Error: {msg}")


def welcome():
    # I would like to make welcome message print better, looks sloppy at the moment
    print("\n" + "="*40)
    print("            NIDS CLI INTERFACE")
    print("="*40)

    print("\nAvailable Commands:\n")

    print("  view [protocol | port] -wait=[ms]")
    print("    • View filtered traffic in real time")
    print("    • Examples:")
    print("        view tcp -wait=500")
    print("        view 80  -wait=500")

    print("\n  exit")
    print("    • Exit the program")

    print("\n" + "="*40 + "\n")


# Validation
def validate_target(arg: str):
    """Validate protocol or port."""
    arg = arg.upper()

    if arg in VALID_PROTOCOLS:
        return arg

    if arg.isdigit():
        port = int(arg)
        if 1 <= port <= 65535:
            return port

    # Arg must either be protocol or port, I intend on adding IP filtering and multifiltering
    raise ValueError(f"'{arg}' is not a supported protocol or port")


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
def parse_command(cmd: str):
    parts = cmd.strip().split()

    if not parts:
        raise ValueError("empty command")

    command = parts[0].lower()

    # I intend on adding other commands in the future, although I am not sure what
    if command != "view":
        raise ValueError(f"'{command}' is not a valid command")

    if len(parts) < 2:
        # If "view" comes alone
        raise ValueError("'view' requires a protocol or port")

    # ie. "tcp", "53", "arp"
    target = validate_target(parts[1])
    wait_ms = parse_wait(parts[2:])

    return {
        "command": "view",
        "target": target,
        "wait_ms": wait_ms,
    }


# CLI loop
def start_cli(packet_queue: Queue, system_stop_event):
    # system_stop_event is the stop event used to exit the entire program
    # Create new stop event for breaking packet stream on keyboard input
    stop_event = threading.Event()
    
    try:
        while not system_stop_event.is_set():
            welcome()
            cmd = input("NIDS> ")
            # Currently all commands are logged, I intend to get rid of this since 
            # normal detection logging has moved to discord.
            add_to_log(f"{cmd}\n", "logs/command_log.txt")

            if cmd.lower() == "exit":
                stop_event.set()
                break

            try:
                parsed = parse_command(cmd)
            except ValueError as e:
                error(str(e))
                continue

            # Stop command listener if an error happens on input to reprompt
            if stop_event:
                stop_event.set()

            # Create new stop event for next input break
            stop_event = threading.Event()

            target = parsed["target"]
            wait_ms = parsed["wait_ms"]

            # If a string is passed, it must be protocol filtered and this will execute
            if isinstance(target, str):
                clear()
                print(f"\nListening for {target} packets (delay={wait_ms}ms)...")
                view_proto(packet_queue, target, stop_event, wait_ms)
            else:
                # Otherwise it must be port filtered and this will execute
                clear()
                print(f"\nListening on port {target} (delay={wait_ms}ms)...")
                view_port(packet_queue, target, stop_event, wait_ms)
                
    # IMPORTANT: This error occurs when all threads stop, this is to catch it and end runtime.
    except EOFError:
        return