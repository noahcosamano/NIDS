from queue import Queue
from utils.welcome import welcome
from utils.ascii import show_ascii
from utils.ui_helpers import error, clear
from cli.commands.view import view_port, view_proto
from cli.parse import parse_command
import time
import threading

# CLI loop
def start_cli(packet_queue: Queue, system_stop_event):
    # system_stop_event is the stop event used to exit the entire program
    # Create new stop event for breaking packet stream on keyboard input
    stop_event = threading.Event()
    
    try:
        show_ascii()
        time.sleep(1.2)
        while not system_stop_event.is_set():
            welcome()
            cmd = input("NIDS> ")

            if cmd.lower() == "exit":
                stop_event.set()
                break

            try:
                parsed = parse_command(packet_queue, cmd, stop_event)
            except ValueError as e:
                error(str(e))
                continue

            # Stop command listener if an error happens on input to reprompt
            if stop_event:
                stop_event.set()

            # Create new stop event for next input break
            stop_event = threading.Event()
                
    # IMPORTANT: This error occurs when all threads stop, this is to catch it and end runtime.
    except EOFError:
        return