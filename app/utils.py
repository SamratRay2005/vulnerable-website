"""
Utility / helper functions.
"""

import requests
from datetime import datetime
from Crypto.Cipher import ARC4, AES

from app.config import LOG_FILE


def log_event(message: str):
    """
    CWE-117 — Log Injection
    User input is written directly into the log file with no sanitization.
    An attacker can inject newline characters to forge log entries.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def insecure_crypto(data: bytes):
    # BANDIT B304: Use of insecure cipher
    cipher1 = ARC4.new(b"key")
    encrypted1 = cipher1.encrypt(data)
    
    # BANDIT B305: Use of insecure cipher mode
    cipher2 = AES.new(b"16bytekey123456", AES.MODE_ECB)
    return cipher2.encrypt(data)

def insecure_requests(url: str):
    # BANDIT B113: Requests without timeout
    response = requests.get(url)
    return response.text

def process_messages(messages):
    for msg in messages:
        # BANDIT B112: Try/except/continue
        try:
            print(msg)
        except Exception:
            continue
