# Developed by: thieveshkar_cb013248
#
# GUI module for the File Integrity Monitor.
# Provides a modern, clean sidebar and tabbed interface.

import os
import time
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk

from core.engine import IntegrityEngine
from core.virustotal import VirusTotalScanner
from core.utils import VT_API_KEY, LOCK_DIR, log_event

class FIMConsole(ctk.CTk):
    """
    The main Graphical User Interface (GUI) built with CustomTkinter.
    Features a modern sidebar and a tabbed layout for improved readability.
    """
    def __init__(self):
        super().__init__()

        self.title("File Integrity Monitor (FIM) - Secure Console")
        self.geometry("1100x700")
        
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")

        self.engine = IntegrityEngine()
        self.vt_scanner = VirusTotalScanner(VT_API_KEY)
        
        self.monitoring_active = False
        self.monitoring_thread = None
        self.monitoring_interval = 60

        self._build_ui()
        self._log("System Initialized. Checking OS and baseline status...")
        
        success, msg = self.engine.load_baseline()
        self._log(msg)

    def _build_ui(self):
        """
        Constructs the graphical layout layers with a Sidebar and Tabview.
        """
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- Sidebar ---
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1)

        logo_label = ctk.CTkLabel(self.sidebar_frame, text="FIM\nConsole", font=ctk.CTkFont(size=24, weight="bold"))
        logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="STATUS:\nIDLE", font=ctk.CTkFont(size=16, weight="bold"), text_color="#00E676")
        self.status_label.grid(row=1, column=0, padx=20, pady=20)

        self.btn_monitor_start = ctk.CTkButton(self.sidebar_frame, text="Start Monitor", fg_color="#00E676", text_color="black", command=self.start_monitoring)
        self.btn_monitor_start.grid(row=2, column=0, padx=20, pady=10)

        self.btn_monitor_stop = ctk.CTkButton(self.sidebar_frame, text="Stop Monitor", fg_color="#E53935", command=self.stop_monitoring, state="disabled")
        self.btn_monitor_stop.grid(row=3, column=0, padx=20, pady=10)

        # Vault lock controls at the bottom of sidebar
        vault_label = ctk.CTkLabel(self.sidebar_frame, text="Vault Controls", font=ctk.CTkFont(size=14, weight="bold"))
        vault_label.grid(row=6, column=0, padx=20, pady=(10, 0))

        self.btn_vault_lock = ctk.CTkButton(self.sidebar_frame, text="Lock Vault", fg_color="#F9A825", text_color="black", command=self.lock_vault)
        self.btn_vault_lock.grid(row=7, column=0, padx=20, pady=(10, 5))

        self.btn_vault_unlock = ctk.CTkButton(self.sidebar_frame, text="Unlock Vault", fg_color="#757575", command=self.unlock_vault)
        self.btn_vault_unlock.grid(row=8, column=0, padx=20, pady=(5, 20))

        # --- Main Content Area (Tabview) ---
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.tabview.add("Dashboard")
        self.tabview.add("System Logs")

        # --- Dashboard Tab ---
        self.tab_dash = self.tabview.tab("Dashboard")
        self.tab_dash.grid_columnconfigure(0, weight=1)
        self.tab_dash.grid_rowconfigure(2, weight=1)

        # Dashboard: Top Config Frame
        config_frame = ctk.CTkFrame(self.tab_dash, fg_color="transparent")
        config_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        config_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(config_frame, text="Target Paths:").grid(row=0, column=0, padx=(0, 10), pady=10, sticky="e")
        self.paths_entry = ctk.CTkEntry(config_frame, placeholder_text="/opt/file_integrity_secure_vault, /var/www/html")
        self.paths_entry.grid(row=0, column=1, padx=(0, 20), pady=10, sticky="ew")

        ctk.CTkLabel(config_frame, text="VT API Key:").grid(row=1, column=0, padx=(0, 10), pady=10, sticky="e")
        self.vt_entry = ctk.CTkEntry(config_frame, show="*")
        self.vt_entry.grid(row=1, column=1, padx=(0, 20), pady=10, sticky="ew")
        self.vt_entry.insert(0, VT_API_KEY)

        # Dashboard: Action Buttons Frame
        action_frame = ctk.CTkFrame(self.tab_dash, fg_color="transparent")
        action_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="ew")

        btn_generate = ctk.CTkButton(action_frame, text="Generate Baseline", fg_color="#2979FF", command=self.run_generate_baseline)
        btn_generate.pack(side="left", padx=(0, 10))

        btn_scan = ctk.CTkButton(action_frame, text="Manual Scan", fg_color="#2979FF", command=self.run_manual_scan)
        btn_scan.pack(side="left")

        # Dashboard: Data Table Frame
        table_frame = ctk.CTkFrame(self.tab_dash)
        table_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#1E1E24", foreground="white", fieldbackground="#1E1E24", borderwidth=0, rowheight=30)
        style.map("Treeview", background=[("selected", "#2979FF")])
        style.configure("Treeview.Heading", background="#2B2B2B", foreground="white", font=("Arial", 11, "bold"))

        # Updated columns
        columns = ("Path", "Status", "Permissions", "Last Modified", "SHA-256", "VirusTotal Score")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
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
            self.tree.column(col, anchor="w", width=w)
        
        self.tree.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns")

        # --- System Logs Tab ---
        self.tab_logs = self.tabview.tab("System Logs")
        self.tab_logs.grid_columnconfigure(0, weight=1)
        self.tab_logs.grid_rowconfigure(0, weight=1)

        self.log_textbox = ctk.CTkTextbox(self.tab_logs, font=("Courier", 12), text_color="#E0E0E0", fg_color="#000000")
        self.log_textbox.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.log_textbox.configure(state="disabled")

    def _log(self, message):
        """
        Inserts a timestamped message into the System Logs tab.
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}\n"
        
        self.log_textbox.configure(state="normal")
        self.log_textbox.insert("end", formatted_msg)
        self.log_textbox.see("end")
        self.log_textbox.configure(state="disabled")

        log_event(message)

    def _get_target_paths(self):
        raw_paths = self.paths_entry.get()
        if not raw_paths.strip():
            return []
        return [p.strip() for p in raw_paths.split(",") if p.strip()]

    def run_generate_baseline(self):
        paths = self._get_target_paths()
        if not paths:
            messagebox.showwarning("No Paths", "Please specify at least one target path.")
            return

        self._log("Starting Baseline Generation...")
        self.status_label.configure(text="STATUS:\nGENERATING", text_color="#F9A825")
        
        def worker():
            success, msg = self.engine.generate_baseline(paths)
            self._log(msg)
            self.status_label.configure(text="STATUS:\nIDLE", text_color="#00E676")
        
        threading.Thread(target=worker, daemon=True).start()

    def _process_scan_results(self, results):
        for row in self.tree.get_children():
            self.tree.delete(row)

        self.vt_scanner.api_key = self.vt_entry.get()

        for res in results:
            path = res["path"]
            status = res["status"]
            file_hash = res["hash"]
            perms = res.get("permissions", "N/A")
            
            raw_mtime = res.get("mtime", 0)
            mtime_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(raw_mtime)) if raw_mtime else "N/A"
            
            vt_score = "N/A"

            if status in ["ADDED", "MODIFIED"]:
                self._log(f"Integrity Alert: {status} file detected at {path}")
            
            if file_hash:
                vt_score = self.vt_scanner.scan_hash(file_hash)
                if status in ["ADDED", "MODIFIED"]:
                    self._log(f"VirusTotal lookup for {file_hash}: {vt_score}")

            self.tree.insert("", "end", values=(path, status, perms, mtime_str, file_hash, vt_score))

    def run_manual_scan(self):
        paths = self._get_target_paths()
        if not paths:
            messagebox.showwarning("No Paths", "Please specify at least one target path.")
            return

        if not self.engine.baseline:
            messagebox.showwarning("No Baseline", "Please generate or load a baseline first.")
            return

        self._log("Starting Manual Scan...")
        self.status_label.configure(text="STATUS:\nSCANNING", text_color="#2979FF")

        def worker():
            results = self.engine.verify_integrity(paths)
            self._process_scan_results(results)
            self._log("Manual Scan Completed.")
            self.status_label.configure(text="STATUS:\nIDLE", text_color="#00E676")
        
        threading.Thread(target=worker, daemon=True).start()

    def _monitoring_loop(self, paths):
        while self.monitoring_active:
            self._log(f"Continuous Monitor Wakeup. Scanning paths: {paths}")
            results = self.engine.verify_integrity(paths)
            self._process_scan_results(results)
            
            for _ in range(self.monitoring_interval):
                if not self.monitoring_active:
                    break
                time.sleep(1)

        self._log("Continuous Monitoring Stopped.")
        self.status_label.configure(text="STATUS:\nIDLE", text_color="#00E676")

    def start_monitoring(self):
        paths = self._get_target_paths()
        if not paths:
            messagebox.showwarning("No Paths", "Please specify at least one target path.")
            return

        if not self.engine.baseline:
            messagebox.showwarning("No Baseline", "Please generate or load a baseline first.")
            return

        self.monitoring_active = True
        self.btn_monitor_start.configure(state="disabled")
        self.btn_monitor_stop.configure(state="normal")
        self.status_label.configure(text="STATUS:\nMONITORING", text_color="#E53935")
        self._log("Starting Continuous Monitoring in the background.")

        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, args=(paths,), daemon=True)
        self.monitoring_thread.start()

    def stop_monitoring(self):
        self.monitoring_active = False
        self.btn_monitor_start.configure(state="normal")
        self.btn_monitor_stop.configure(state="disabled")
        self._log("Sent stop signal to monitoring thread...")

    def lock_vault(self):
        paths = self._get_target_paths()
        if not paths:
            self._log("[ERROR] No target path specified to lock.")
            messagebox.showwarning("No Paths", "Please specify at least one target path to lock.")
            return

        for target in paths:
            self._log(f"Attempting to apply system-level vault lock (chattr -R +i) to {target}")
            if not os.path.exists(target):
                self._log(f"[ERROR] Target directory {target} does not exist.")
                continue

            try:
                # Includes -R for recursive locking of files and subdirectories
                result = subprocess.run(["sudo", "chattr", "-R", "+i", target], capture_output=True, text=True)
                if result.returncode == 0:
                    self._log(f"Vault successfully locked. Directory {target} and its contents are now immutable.")
                    messagebox.showinfo("Vault Locked", f"The directory {target} and its contents are now immutable.")
                else:
                    self._log(f"[ERROR] Vault lock failed for {target}: {result.stderr}")
                    messagebox.showerror("Vault Lock Error", f"Failed to apply lock to {target}:\n{result.stderr}")
            except FileNotFoundError:
                self._log("[ERROR] 'chattr' command not found. Is this a Linux environment?")
            except Exception as e:
                self._log(f"[ERROR] Vault lock exception for {target}: {e}")

    def unlock_vault(self):
        paths = self._get_target_paths()
        if not paths:
            self._log("[ERROR] No target path specified to unlock.")
            messagebox.showwarning("No Paths", "Please specify at least one target path to unlock.")
            return

        for target in paths:
            self._log(f"Attempting to remove system-level vault lock (chattr -R -i) from {target}")
            if not os.path.exists(target):
                self._log(f"[ERROR] Target directory {target} does not exist.")
                continue

            try:
                # Includes -R for recursive unlocking of files and subdirectories
                result = subprocess.run(["sudo", "chattr", "-R", "-i", target], capture_output=True, text=True)
                if result.returncode == 0:
                    self._log(f"Vault successfully unlocked. Directory {target} and its contents are now mutable.")
                    messagebox.showinfo("Vault Unlocked", f"The directory {target} and its contents are now mutable.")
                else:
                    self._log(f"[ERROR] Vault unlock failed for {target}: {result.stderr}")
                    messagebox.showerror("Vault Unlock Error", f"Failed to remove lock from {target}:\n{result.stderr}")
            except FileNotFoundError:
                self._log("[ERROR] 'chattr' command not found. Is this a Linux environment?")
            except Exception as e:
                self._log(f"[ERROR] Vault unlock exception for {target}: {e}")