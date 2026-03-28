import threading
import requests
import time

WEBHOOK_URL = "https://discord.com/api/webhooks/1487319812026798140/6xQQHqux3fM2GoFXw9lWsSSce0ln5z2POw-1NW0s2dUrH9-tv0MhGZZXo2N5i51gWQ3F"

def add_to_log(message, file_name):
    with open(file_name, mode="a") as file:
        file.writelines(message)
        
def log_event(message):
    thread_name = threading.current_thread().name
    print(f"[{thread_name}-THREAD] {message}")
    
def report_to_webhook(detection_type, content):
    content_str = str(content)

    data = {
        "username": "NIDS",
        "avatar_url": "https://fbi.cults3d.com/uploaders/40342033/illustration-file/9993ed82-301c-4ad4-8f63-4597b8337458/le%C3%B1ador-clash.png",
        "embeds": [
            {
                "title": str(detection_type),
                "description": content_str,
                "color": 16711680, # Red
                "author": {
                    "name": "Network Intrusion Detection System" # Must be an object with a 'name' key
                },
            }
        ]
    }
    
    try:
        # Using json=data automatically sets Content-Type: application/json
        response = requests.post(WEBHOOK_URL, json=data, timeout=5)
        
        if response.status_code == 204:
            print("Successfully reported to webhook.")
        else:
            print(f"Failed to send message: {response.status_code}")
            print(f"Response Body: {response.text}") # This tells you EXACTLY what is wrong
    except Exception as e:
        print(f"Webhook connection error: {e}")