# Developed by: thieveshkar_cb013248
#
# Utilities module for the File Integrity Monitor.
# Contains constants, logging, and system-level checks.

import os
import sys
import time
import tkinter as tk
from tkinter import messagebox

# Global VirusTotal API Key - Enter your own Virus Total API Key
VT_API_KEY = ""

# System Paths Configuration
VAULT_DIR = "/var/lib/file_integrity_secure_vault"
BASELINE_PATH = os.path.join(VAULT_DIR, ".baseline.json")
LOG_PATH = "/var/log/file_integrity_secure_vault.log"
LOCK_DIR = "/opt/file_integrity_secure_vault"

def check_root_privileges():
    """
    Checks if the script is running with root privileges (UID 0).
    If not, displays a graphical or terminal error and exits.
    """
    try:
        if os.geteuid() != 0:
            root_tk = tk.Tk()
            root_tk.withdraw()
            messagebox.showerror("Access Denied", "Access Denied: Root privileges required to monitor secure file paths.")
            sys.exit(1)
    except AttributeError:
        print("[WARNING] OS does not support os.geteuid(). Assuming root or testing mode.")

def log_event(message):
    """
    Appends a timestamped message to the local system log.
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    formatted_msg = f"[{timestamp}] {message}\n"
    try:
        with open(LOG_PATH, "a") as f:
            f.write(formatted_msg)
    except Exception as e:
        print(f"[ERROR] Could not write to log: {e}")
