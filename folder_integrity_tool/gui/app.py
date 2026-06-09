# Developed by: thieveshkar_cb013248
#
# GUI module for the File Integrity Monitor.
# Provides a modern, clean sidebar and tabbed interface.

# Import the 'os' module for interacting with the operating system (e.g., file paths)
import os
# Import the 'time' module to work with time delays and formatting timestamps
import time
# Import the 'threading' module to run tasks in the background without freezing the GUI
import threading
# Import the 'subprocess' module to run external system commands (like locking folders)
import subprocess
# Import the 'tkinter' module for creating standard graphical user interfaces
import tkinter as tk
# Import 'ttk' for themed tkinter widgets, and 'messagebox' for pop-up alerts
from tkinter import ttk, messagebox
# Import 'customtkinter' for creating modern, dark-mode friendly GUI elements
import customtkinter as ctk

# Import the IntegrityEngine class from our core engine module to handle file scanning
from core.engine import IntegrityEngine
# Import the VirusTotalScanner class from our core virustotal module to check file hashes
from core.virustotal import VirusTotalScanner
# Import global variables (API Key, Lock directory) and the logging function from our utils module
from core.utils import VT_API_KEY, LOCK_DIR, log_event

# Define the main graphical window class, inheriting from customtkinter's CTk window
class FIMConsole(ctk.CTk):
    """
    The main Graphical User Interface (GUI) built with CustomTkinter.
    Features a modern sidebar and a tabbed layout for improved readability.
    """
    # The initialization method that runs when the GUI window is created
    def __init__(self):
        # Call the parent class's initialization method to set up the window
        super().__init__()

        # Set the title that appears at the top of the window
        self.title("File Integrity Monitor (FIM) - Secure Console")
        # Set the default size of the window to 1100 pixels wide by 700 pixels high
        self.geometry("1100x700")
        
        # Set the appearance mode to 'dark' for a modern look
        ctk.set_appearance_mode("dark")
        # Set the default color theme to 'green' so buttons and accents are green
        ctk.set_default_color_theme("green")

        # Create an instance of the IntegrityEngine to handle backend scanning
        self.engine = IntegrityEngine()
        # Create an instance of the VirusTotalScanner using our API key
        self.vt_scanner = VirusTotalScanner(VT_API_KEY)
        
        # A flag to track whether continuous monitoring is currently running
        self.monitoring_active = False
        # A variable to hold the background thread that will do the monitoring
        self.monitoring_thread = None
        # Set the time interval (in seconds) for how often the monitor checks files (60 seconds)
        self.monitoring_interval = 60

        # Call the helper method to build all the graphical elements (buttons, text boxes, etc.)
        self._build_ui()
        # Log a message indicating the system has started
        self._log("System Initialized. Checking OS and baseline status...")
        
        # Attempt to load an existing file baseline from the secure vault
        success, msg = self.engine.load_baseline()
        # Log the result of the baseline loading attempt
        self._log(msg)

    # Method to construct the user interface layout
    def _build_ui(self):
        """
        Constructs the graphical layout layers with a Sidebar and Tabview.
        """
        # Configure the grid layout: column 1 will stretch to fill available horizontal space
        self.grid_columnconfigure(1, weight=1)
        # Configure the grid layout: row 0 will stretch to fill available vertical space
        self.grid_rowconfigure(0, weight=1)

        # --- Sidebar ---
        # Create a frame for the sidebar on the left side of the window
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        # Place the sidebar in the grid at row 0, column 0, stretching it up, down, left, and right
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        # Configure row 5 inside the sidebar to stretch, pushing elements below it to the bottom
        self.sidebar_frame.grid_rowconfigure(5, weight=1)

        # Create a large, bold label for the logo text "FIM Console"
        logo_label = ctk.CTkLabel(self.sidebar_frame, text="FIM\nConsole", font=ctk.CTkFont(size=24, weight="bold"))
        # Place the logo at the top of the sidebar with some padding
        logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Create a label to display the current status of the monitor (e.g., IDLE, SCANNING)
        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="STATUS:\nIDLE", font=ctk.CTkFont(size=16, weight="bold"), text_color="#00E676")
        # Place the status label below the logo
        self.status_label.grid(row=1, column=0, padx=20, pady=20)

        # Create a button to start continuous monitoring, colored green
        self.btn_monitor_start = ctk.CTkButton(self.sidebar_frame, text="Start Monitor", fg_color="#00E676", text_color="black", command=self.start_monitoring)
        # Place the start button in the sidebar
        self.btn_monitor_start.grid(row=2, column=0, padx=20, pady=10)

        # Create a button to stop continuous monitoring, colored red, and disabled by default
        self.btn_monitor_stop = ctk.CTkButton(self.sidebar_frame, text="Stop Monitor", fg_color="#E53935", command=self.stop_monitoring, state="disabled")
        # Place the stop button below the start button
        self.btn_monitor_stop.grid(row=3, column=0, padx=20, pady=10)

        # Vault lock controls at the bottom of sidebar
        # Create a label for the vault controls section
        vault_label = ctk.CTkLabel(self.sidebar_frame, text="Vault Controls", font=ctk.CTkFont(size=14, weight="bold"))
        # Place the label near the bottom of the sidebar
        vault_label.grid(row=6, column=0, padx=20, pady=(10, 0))

        # Create a button to lock the vault directory, colored yellow/orange
        self.btn_vault_lock = ctk.CTkButton(self.sidebar_frame, text="Lock Vault", fg_color="#F9A825", text_color="black", command=self.lock_vault)
        # Place the lock button in the sidebar
        self.btn_vault_lock.grid(row=7, column=0, padx=20, pady=(10, 5))

        # Create a button to unlock the vault directory, colored grey
        self.btn_vault_unlock = ctk.CTkButton(self.sidebar_frame, text="Unlock Vault", fg_color="#757575", command=self.unlock_vault)
        # Place the unlock button at the very bottom of the sidebar
        self.btn_vault_unlock.grid(row=8, column=0, padx=20, pady=(5, 20))

        # --- Main Content Area (Tabview) ---
        # Create a tabbed view area for the main content
        self.tabview = ctk.CTkTabview(self)
        # Place the tabbed view to the right of the sidebar, filling the remaining space
        self.tabview.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        # Add a tab named "Dashboard"
        self.tabview.add("Dashboard")
        # Add a tab named "System Logs"
        self.tabview.add("System Logs")

        # --- Dashboard Tab ---
        # Get a reference to the Dashboard tab
        self.tab_dash = self.tabview.tab("Dashboard")
        # Configure the layout of the Dashboard tab to stretch horizontally
        self.tab_dash.grid_columnconfigure(0, weight=1)
        # Configure the layout to stretch vertically (specifically the data table row)
        self.tab_dash.grid_rowconfigure(2, weight=1)

        # Dashboard: Top Config Frame
        # Create a transparent frame at the top for user inputs (paths, API key)
        config_frame = ctk.CTkFrame(self.tab_dash, fg_color="transparent")
        # Place it at the top of the Dashboard tab
        config_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        # Allow the input fields inside this frame to stretch horizontally
        config_frame.grid_columnconfigure(1, weight=1)

        # Create a label for the Target Paths input
        ctk.CTkLabel(config_frame, text="Target Paths:").grid(row=0, column=0, padx=(0, 10), pady=10, sticky="e")
        # Create an entry box where the user can type the paths they want to monitor
        self.paths_entry = ctk.CTkEntry(config_frame, placeholder_text="/opt/file_integrity_secure_vault, /var/www/html")
        # Place the entry box next to the label, stretching to fill space
        self.paths_entry.grid(row=0, column=1, padx=(0, 20), pady=10, sticky="ew")

        # Create a label for the VirusTotal API Key input
        ctk.CTkLabel(config_frame, text="VT API Key:").grid(row=1, column=0, padx=(0, 10), pady=10, sticky="e")
        # Create an entry box for the API key, masking the characters with asterisks (*) for security
        self.vt_entry = ctk.CTkEntry(config_frame, show="*")
        # Place the entry box next to its label
        self.vt_entry.grid(row=1, column=1, padx=(0, 20), pady=10, sticky="ew")
        # Automatically insert the default API key from our utils module
        self.vt_entry.insert(0, VT_API_KEY)

        # Dashboard: Action Buttons Frame
        # Create a transparent frame to hold the action buttons
        action_frame = ctk.CTkFrame(self.tab_dash, fg_color="transparent")
        # Place it below the configuration frame
        action_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="ew")

        # Create a button to manually generate a new baseline
        btn_generate = ctk.CTkButton(action_frame, text="Generate Baseline", fg_color="#2979FF", command=self.run_generate_baseline)
        # Pack it to the left side of the action frame
        btn_generate.pack(side="left", padx=(0, 10))

        # Create a button to run a manual file scan immediately
        btn_scan = ctk.CTkButton(action_frame, text="Manual Scan", fg_color="#2979FF", command=self.run_manual_scan)
        # Pack it to the left, next to the generate button
        btn_scan.pack(side="left")

        # Dashboard: Data Table Frame
        # Create a frame to hold the table that will display scan results
        table_frame = ctk.CTkFrame(self.tab_dash)
        # Place it at the bottom of the Dashboard tab, stretching to fill space
        table_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")
        # Configure the frame to stretch the table properly
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        # Create a style object to customize the look of the table (Treeview)
        style = ttk.Style()
        # Set the base theme to 'default'
        style.theme_use("default")
        # Customize the table background, text color, and row height to fit the dark theme
        style.configure("Treeview", background="#1E1E24", foreground="white", fieldbackground="#1E1E24", borderwidth=0, rowheight=30)
        # Customize the highlight color when a row is selected
        style.map("Treeview", background=[("selected", "#2979FF")])
        # Customize the table headers (background color, text color, font)
        style.configure("Treeview.Heading", background="#2B2B2B", foreground="white", font=("Arial", 11, "bold"))

        # Define the column names for the table
        columns = ("Path", "Status", "Permissions", "Last Modified", "SHA-256", "VirusTotal Score")
        # Create the Treeview widget (the actual table)
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        # Loop through the column names and set up each column's header and width
        for col in columns:
            # Set the header text
            self.tree.heading(col, text=col)
            # Define specific widths for different columns to make data fit nicely
            if col == "Path":
                w = 250
            elif col == "SHA-256":
                w = 150
            elif col == "Last Modified":
                w = 140
            elif col == "Permissions":
                w = 90
            else:
                w = 110
            # Apply the width and align the text to the left ("w" for west)
            self.tree.column(col, anchor="w", width=w)
        
        # Place the table in the frame, making it stretch
        self.tree.grid(row=0, column=0, sticky="nsew")

        # Create a vertical scrollbar for the table
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        # Link the scrollbar to the table so they move together
        self.tree.configure(yscroll=scrollbar.set)
        # Place the scrollbar on the right side of the table
        scrollbar.grid(row=0, column=1, sticky="ns")

        # --- System Logs Tab ---
        # Get a reference to the System Logs tab
        self.tab_logs = self.tabview.tab("System Logs")
        # Configure layout to stretch to fill space
        self.tab_logs.grid_columnconfigure(0, weight=1)
        self.tab_logs.grid_rowconfigure(0, weight=1)

        # Create a large text box to display log messages
        self.log_textbox = ctk.CTkTextbox(self.tab_logs, font=("Courier", 12), text_color="#E0E0E0", fg_color="#000000")
        # Place the text box in the tab, stretching to fill space
        self.log_textbox.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        # Set the text box state to 'disabled' so the user cannot type in it manually
        self.log_textbox.configure(state="disabled")

    # Helper method to log messages to the GUI text box and the system log file
    def _log(self, message):
        """
        Inserts a timestamped message into the System Logs tab.
        """
        # Generate a timestamp for right now
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        # Format the message to include the timestamp
        formatted_msg = f"[{timestamp}] {message}\n"
        
        # Temporarily enable the text box so we can insert text
        self.log_textbox.configure(state="normal")
        # Insert the message at the end of the text box
        self.log_textbox.insert("end", formatted_msg)
        # Automatically scroll down so the newest message is visible
        self.log_textbox.see("end")
        # Disable the text box again so the user can't edit it
        self.log_textbox.configure(state="disabled")

        # Call the log_event function from our utils to also write this to the log file on disk
        log_event(message)

    # Helper method to get and process the target paths from the user input field
    def _get_target_paths(self):
        # Get the text the user typed into the paths entry box
        raw_paths = self.paths_entry.get()
        # If the box is empty, return an empty list
        if not raw_paths.strip():
            return []
        # Split the text by commas, remove any extra spaces from each path, and return as a list
        return [p.strip() for p in raw_paths.split(",") if p.strip()]

    # Method called when the user clicks 'Generate Baseline'
    def run_generate_baseline(self):
        # Get the target paths from the user
        paths = self._get_target_paths()
        # If no paths were entered, show a warning message and stop
        if not paths:
            messagebox.showwarning("No Paths", "Please specify at least one target path.")
            return

        # Log that we are starting the baseline generation
        self._log("Starting Baseline Generation...")
        # Update the status label to show we are generating
        self.status_label.configure(text="STATUS:\nGENERATING", text_color="#F9A825")
        
        # Define a worker function to run in the background so the GUI doesn't freeze
        def worker():
            # Call the engine to generate the baseline
            success, msg = self.engine.generate_baseline(paths)
            # Log the result message
            self._log(msg)
            # Reset the status label back to IDLE
            self.status_label.configure(text="STATUS:\nIDLE", text_color="#00E676")
        
        # Start a new background thread to run the worker function
        threading.Thread(target=worker, daemon=True).start()

    # Helper method to display scan results in the data table
    def _process_scan_results(self, results):
        # Loop through all existing rows in the table and delete them to clear old results
        for row in self.tree.get_children():
            self.tree.delete(row)

        # Update the VirusTotal scanner with whatever API key is currently typed in the entry box
        self.vt_scanner.api_key = self.vt_entry.get()

        # Loop through each result (each changed/added/deleted file) returned by the engine
        for res in results:
            # Extract the file path
            path = res["path"]
            # Extract the file status (ADDED, MODIFIED, MATCHED, DELETED)
            status = res["status"]
            # Extract the file hash
            file_hash = res["hash"]
            # Extract the permissions, or use "N/A" if missing
            perms = res.get("permissions", "N/A")
            
            # Extract the raw modification time
            raw_mtime = res.get("mtime", 0)
            # Convert the raw time into a readable date/time string
            mtime_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(raw_mtime)) if raw_mtime else "N/A"
            
            # Default the VirusTotal score to "N/A"
            vt_score = "N/A"

            # If the file was added or modified, we log an alert
            if status in ["ADDED", "MODIFIED"]:
                self._log(f"Integrity Alert: {status} file detected at {path}")
            
            # If we have a hash for the file
            if file_hash:
                # Query VirusTotal to see if the file is malicious
                vt_score = self.vt_scanner.scan_hash(file_hash)
                # Log the VirusTotal score if the file was added or modified
                if status in ["ADDED", "MODIFIED"]:
                    self._log(f"VirusTotal lookup for {file_hash}: {vt_score}")

            # Insert a new row into the table with all the data
            self.tree.insert("", "end", values=(path, status, perms, mtime_str, file_hash, vt_score))

    # Method called when the user clicks 'Manual Scan'
    def run_manual_scan(self):
        # Get the target paths from the user
        paths = self._get_target_paths()
        # If no paths were entered, show a warning
        if not paths:
            messagebox.showwarning("No Paths", "Please specify at least one target path.")
            return

        # If there is no baseline loaded, show a warning because we need something to compare against
        if not self.engine.baseline:
            messagebox.showwarning("No Baseline", "Please generate or load a baseline first.")
            return

        # Log that we are starting a manual scan
        self._log("Starting Manual Scan...")
        # Update the status label to show we are scanning
        self.status_label.configure(text="STATUS:\nSCANNING", text_color="#2979FF")

        # Define a worker function to run the scan in the background
        def worker():
            # Call the engine to verify integrity (compare current files to the baseline)
            results = self.engine.verify_integrity(paths)
            # Process the results and update the table
            self._process_scan_results(results)
            # Log that the scan is complete
            self._log("Manual Scan Completed.")
            # Reset the status label to IDLE
            self.status_label.configure(text="STATUS:\nIDLE", text_color="#00E676")
        
        # Start a new background thread to run the worker function
        threading.Thread(target=worker, daemon=True).start()

    # The background loop that continuously monitors the files
    def _monitoring_loop(self, paths):
        # Keep running as long as the monitoring_active flag is True
        while self.monitoring_active:
            # Log that the monitor is waking up to scan
            self._log(f"Continuous Monitor Wakeup. Scanning paths: {paths}")
            # Call the engine to verify integrity
            results = self.engine.verify_integrity(paths)
            # Process the results and update the table
            self._process_scan_results(results)
            
            # Sleep for the set interval (e.g., 60 seconds), checking every second if we should stop
            for _ in range(self.monitoring_interval):
                # If the user clicked Stop, the flag becomes False, so we break out of the sleep loop
                if not self.monitoring_active:
                    break
                # Sleep for 1 second
                time.sleep(1)

        # Log that monitoring has stopped
        self._log("Continuous Monitoring Stopped.")
        # Reset the status label to IDLE
        self.status_label.configure(text="STATUS:\nIDLE", text_color="#00E676")

    # Method called when the user clicks 'Start Monitor'
    def start_monitoring(self):
        # Get the target paths
        paths = self._get_target_paths()
        # Ensure paths exist
        if not paths:
            messagebox.showwarning("No Paths", "Please specify at least one target path.")
            return

        # Ensure a baseline exists
        if not self.engine.baseline:
            messagebox.showwarning("No Baseline", "Please generate or load a baseline first.")
            return

        # Set the flag to True so the loop will run
        self.monitoring_active = True
        # Disable the Start button so it can't be clicked again
        self.btn_monitor_start.configure(state="disabled")
        # Enable the Stop button
        self.btn_monitor_stop.configure(state="normal")
        # Update the status label
        self.status_label.configure(text="STATUS:\nMONITORING", text_color="#E53935")
        # Log the start event
        self._log("Starting Continuous Monitoring in the background.")

        # Create and start the background thread for continuous monitoring
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, args=(paths,), daemon=True)
        self.monitoring_thread.start()

    # Method called when the user clicks 'Stop Monitor'
    def stop_monitoring(self):
        # Set the flag to False to tell the background loop to stop
        self.monitoring_active = False
        # Re-enable the Start button
        self.btn_monitor_start.configure(state="normal")
        # Disable the Stop button
        self.btn_monitor_stop.configure(state="disabled")
        # Log that we sent the stop signal
        self._log("Sent stop signal to monitoring thread...")

    # Method called when the user clicks 'Lock Vault'
    def lock_vault(self):
        # Get target paths to lock
        paths = self._get_target_paths()
        # If no paths specified, show an error
        if not paths:
            self._log("[ERROR] No target path specified to lock.")
            messagebox.showwarning("No Paths", "Please specify at least one target path to lock.")
            return

        # Loop through each path provided
        for target in paths:
            # Log the attempt to lock
            self._log(f"Attempting to apply system-level vault lock (chattr -R +i) to {target}")
            # Check if the folder actually exists
            if not os.path.exists(target):
                self._log(f"[ERROR] Target directory {target} does not exist.")
                continue

            try:
                # Includes -R for recursive locking of files and subdirectories
                # Run the Linux command 'chattr +i' (change attribute to immutable) using sudo
                result = subprocess.run(["sudo", "chattr", "-R", "+i", target], capture_output=True, text=True)
                # If the command was successful (return code 0)
                if result.returncode == 0:
                    # Log success
                    self._log(f"Vault successfully locked. Directory {target} and its contents are now immutable.")
                    # Show a pop-up success message
                    messagebox.showinfo("Vault Locked", f"The directory {target} and its contents are now immutable.")
                else:
                    # Log the error if the command failed
                    self._log(f"[ERROR] Vault lock failed for {target}: {result.stderr}")
                    # Show a pop-up error message
                    messagebox.showerror("Vault Lock Error", f"Failed to apply lock to {target}:\n{result.stderr}")
            # Catch error if the 'chattr' command doesn't exist (like on Windows)
            except FileNotFoundError:
                self._log("[ERROR] 'chattr' command not found. Is this a Linux environment?")
            # Catch any other unexpected errors
            except Exception as e:
                self._log(f"[ERROR] Vault lock exception for {target}: {e}")

    # Method called when the user clicks 'Unlock Vault'
    def unlock_vault(self):
        # Get target paths to unlock
        paths = self._get_target_paths()
        # If no paths specified, show an error
        if not paths:
            self._log("[ERROR] No target path specified to unlock.")
            messagebox.showwarning("No Paths", "Please specify at least one target path to unlock.")
            return

        # Loop through each path provided
        for target in paths:
            # Log the attempt to unlock
            self._log(f"Attempting to remove system-level vault lock (chattr -R -i) from {target}")
            # Check if the folder actually exists
            if not os.path.exists(target):
                self._log(f"[ERROR] Target directory {target} does not exist.")
                continue

            try:
                # Includes -R for recursive unlocking of files and subdirectories
                # Run the Linux command 'chattr -i' (remove immutable attribute) using sudo
                result = subprocess.run(["sudo", "chattr", "-R", "-i", target], capture_output=True, text=True)
                # If the command was successful
                if result.returncode == 0:
                    # Log success
                    self._log(f"Vault successfully unlocked. Directory {target} and its contents are now mutable.")
                    # Show a pop-up success message
                    messagebox.showinfo("Vault Unlocked", f"The directory {target} and its contents are now mutable.")
                else:
                    # Log the error if the command failed
                    self._log(f"[ERROR] Vault unlock failed for {target}: {result.stderr}")
                    # Show a pop-up error message
                    messagebox.showerror("Vault Unlock Error", f"Failed to remove lock from {target}:\n{result.stderr}")
            # Catch error if the 'chattr' command doesn't exist
            except FileNotFoundError:
                self._log("[ERROR] 'chattr' command not found. Is this a Linux environment?")
            # Catch any other unexpected errors
            except Exception as e:
                self._log(f"[ERROR] Vault unlock exception for {target}: {e}")
