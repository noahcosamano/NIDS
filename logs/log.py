import threading

def add_to_log(message, file_name):
    with open(file_name, mode="a") as file:
        file.writelines(message)
        
def log_event(message):
    thread_name = threading.current_thread().name
    print(f"[{thread_name}-THREAD] {message}")