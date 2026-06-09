# Developed by: thieveshkar_cb013248
#
# Utilities module for the File Integrity Monitor.
# Contains constants, logging, and system-level checks.

# Import the 'os' module to interact with the operating system (e.g., file paths, permissions)
import os
# Import the 'sys' module to access system-specific parameters and functions like exiting the program
import sys
# Import the 'time' module to work with time-related functions, such as getting the current time for logs
import time
# Import the 'tkinter' module, giving it the alias 'tk', which is the standard Python library for creating Graphical User Interfaces (GUIs)
import tkinter as tk
# Import the 'messagebox' component from 'tkinter' to display pop-up alert boxes to the user
from tkinter import messagebox

# Global VirusTotal API Key
# This is a unique secret key used to authenticate with the VirusTotal service to check if files are malicious
VT_API_KEY = "your_personal_virustotal_api_key_here"

# System Paths Configuration
# This defines the directory where the application will store its secure data, like the baseline of safe files
VAULT_DIR = "/var/lib/file_integrity_secure_vault"
# This combines the vault directory path with the file name '.baseline.json' to get the full path for the baseline file
BASELINE_PATH = os.path.join(VAULT_DIR, ".baseline.json")
# This defines the path where the application will save its log files to record events
LOG_PATH = "/var/log/file_integrity_secure_vault.log"
# This defines a directory path that can be locked to prevent unauthorized changes
LOCK_DIR = "/opt/file_integrity_secure_vault"

# Define a function to check if the user has Administrator or Root privileges
def check_root_privileges():
    """
    Checks if the script is running with root privileges (UID 0).
    If not, displays a graphical or terminal error and exits.
    """
    try:
        # Check if the Effective User ID is not 0 (0 means root/administrator on Linux/Unix systems)
        if os.geteuid() != 0:
            # Create a hidden main window using tkinter
            root_tk = tk.Tk()
            # Hide the main window so only the error message box is visible
            root_tk.withdraw()
            # Show a graphical error message box telling the user they are denied access
            messagebox.showerror("Access Denied", "Access Denied: Root privileges required to monitor secure file paths.")
            # Exit the program with an error status code of 1
            sys.exit(1)
    # If the system does not support 'os.geteuid()' (for example, on Windows), catch the error
    except AttributeError:
        # Print a warning message to the console instead of crashing, assuming the user might be testing on Windows
        print("[WARNING] OS does not support os.geteuid(). Assuming root or testing mode.")

# Define a function to log messages with a timestamp
def log_event(message):
    """
    Appends a timestamped message to the local system log.
    """
    # Get the current time and format it as 'Year-Month-Day Hour:Minute:Second'
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    # Combine the timestamp and the log message into a single formatted string with a new line at the end
    formatted_msg = f"[{timestamp}] {message}\n"
    try:
        # Open the log file in 'append' mode ("a"), so we add to it without deleting existing logs
        with open(LOG_PATH, "a") as f:
            # Write the formatted log message into the file
            f.write(formatted_msg)
    # If an error occurs (like not having permission to write to the file), catch the error
    except Exception as e:
        # Print an error message to the console showing what went wrong
        print(f"[ERROR] Could not write to log: {e}")
