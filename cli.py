from queue import Queue
import threading
from view_packets import view_proto, view_port
from log import add_to_log
import os

VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "IGMP", "ALL"}

def welcome():
    print("\n=== NIDS CLI ===")
    print("Commands:")
    print("  view [protocol|port] -wait=[milliseconds]")
    print("    example: view tcp -wait=500")
    print("    example: view 80 -wait=500")
    print("  exit\n")


def parse_command(cmd: str):
    parts = cmd.strip().split()

    if len(parts) < 1:
        return None, None

    if parts[0].lower() != "view":
        os.system("cls")
        print(f" Error: '{parts[0]}' is not a valid command")
        return None, None
    
    if len(parts) < 2:
        os.system("cls")
        print(f" Error: 'view' requires 2 arguments, 0 were given")
        return None, None

    arg = parts[1].upper()

    if not validate_arg(arg):
        return None, None

    wait_ms = 0

    for part in parts[2:]:
        if part.startswith("-wait=") or part == None:
            try:
                wait_ms = int(part.split("=")[1])
            except ValueError:
                os.system("cls")
                print(" Error: wait must be an integer")
                return None, None
        else:
            os.system("cls")
            print(f" Error: 'delay=[milliseconds]' argument is missing")
            return None, None

    return arg, wait_ms


def validate_arg(arg):
    if arg in VALID_PROTOCOLS:
        return True

    if arg.isdigit():
        port = int(arg)
        if 1 <= port <= 65535:
            return True

    os.system("cls")
    print(f" Error: '{arg}' is not a valid protocol or port")
    return False


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

        arg, wait_ms = parse_command(cmd)

        if arg is None or wait_ms is None:
            continue

        if stop_event:
            stop_event.set()
        if worker_thread:
            worker_thread.join()

        stop_event = threading.Event()

        if arg in VALID_PROTOCOLS:
            print(f"\nListening for {arg} packets (delay={wait_ms}s)...")
            view_proto(packet_queue, arg, stop_event, wait_ms)
        else:
            port = int(arg)
            print(f"\nListening on port {port} (delay={wait_ms}s)...")
            view_port(packet_queue, port, stop_event, wait_ms)