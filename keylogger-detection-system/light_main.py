import os
import sys
import psutil
import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk
import threading
import time
from datetime import datetime
import subprocess
import pwd
import grp


class LinuxKeyloggerDetector:
    def __init__(self):
        self.suspicious_keywords = [
            "keylog",
            "keycap",
            "keystroke",
            "keyrecord",
            "logkeys",
            "keysniff",
            "keymonitor",
            "inputlog",
            "screenlog",
            "spyware",
            "logger",
            "capture",
            "xinput",
            "xev",
            "xdotool",
            "hook",
        ]
        self.suspicious_paths = [
            "/tmp/",
            "/var/tmp/",
            "/dev/shm/",
            "/.",
            "/home/.*/.cache",
            "/home/.*/tmp",
            "/run/user",
        ]
        self.xorg_monitors = ["xinput", "xev", "xdotool", "xprop"]
        self.monitoring = False

    def calculate_threat_score(self, proc_info):
        """Calculate threat score based on multiple factors"""
        score = 0
        name = proc_info.get("name", "").lower()
        exe_path = (proc_info.get("exe") or "").lower()
        cmdline = " ".join(proc_info.get("cmdline", [])).lower()

        # Check for suspicious keywords (30 points)
        for keyword in self.suspicious_keywords:
            if keyword in name or keyword in exe_path or keyword in cmdline:
                score += 30
                break

        # Check for suspicious paths (25 points)
        for path in self.suspicious_paths:
            if path in exe_path:
                score += 25
                break

        # Check if running from hidden directory (20 points)
        if (
            "/." in exe_path
            or exe_path.startswith("/tmp")
            or exe_path.startswith("/dev/shm")
        ):
            score += 20

        # Check for X11 input monitoring tools (25 points)
        if any(tool in name for tool in self.xorg_monitors):
            if "test" not in cmdline and "debug" not in cmdline:
                score += 25

        # Check for processes reading /dev/input (30 points)
        try:
            proc = psutil.Process(proc_info["pid"])
            for file in proc.open_files():
                if "/dev/input" in file.path:
                    score += 30
                    break
        except:
            pass

        # Check CPU usage (10 points if very low - keyloggers are stealthy)
        try:
            proc = psutil.Process(proc_info["pid"])
            cpu_percent = proc.cpu_percent(interval=0.1)
            if cpu_percent < 0.5 and cpu_percent > 0:
                score += 10
        except:
            pass

        # Check if running as root but started from user context (15 points)
        try:
            if proc_info.get("username") == "root" and os.getuid() != 0:
                score += 15
        except:
            pass

        return min(score, 100)

    def check_systemd_services(self):
        """Check for suspicious systemd services"""
        suspicious = []
        try:
            result = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--all", "--no-pager"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            services = result.stdout.split("\n")

            for service in services:
                service_lower = service.lower()
                if any(
                    keyword in service_lower for keyword in self.suspicious_keywords
                ):
                    parts = service.split()
                    if parts:
                        suspicious.append(
                            {
                                "name": parts[0],
                                "status": "active"
                                if "active" in service_lower
                                else "inactive",
                                "description": " ".join(parts[4:])
                                if len(parts) > 4
                                else "N/A",
                            }
                        )
        except Exception as e:
            print(f"Error checking systemd services: {e}")

        return suspicious

    def check_startup_entries(self):
        """Check various Linux startup locations"""
        suspicious = []

        # Check user autostart
        autostart_paths = [
            os.path.expanduser("~/.config/autostart/"),
            "/etc/xdg/autostart/",
            os.path.expanduser("~/.config/systemd/user/"),
            "/etc/systemd/system/",
        ]

        for path in autostart_paths:
            if not os.path.exists(path):
                continue

            try:
                for filename in os.listdir(path):
                    filepath = os.path.join(path, filename)
                    if os.path.isfile(filepath):
                        with open(filepath, "r", errors="ignore") as f:
                            content = f.read().lower()

                        if any(
                            keyword in content or keyword in filename.lower()
                            for keyword in self.suspicious_keywords
                        ):
                            suspicious.append(
                                {
                                    "name": filename,
                                    "path": filepath,
                                    "location": path,
                                    "threat": "High",
                                }
                            )
            except Exception as e:
                continue

        # Check crontab
        try:
            result = subprocess.run(
                ["crontab", "-l"], capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    line_lower = line.lower()
                    if any(
                        keyword in line_lower for keyword in self.suspicious_keywords
                    ):
                        suspicious.append(
                            {
                                "name": "Crontab Entry",
                                "path": line.strip(),
                                "location": "User Crontab",
                                "threat": "High",
                            }
                        )
        except:
            pass

        return suspicious

    def check_network_connections(self):
        """Check for suspicious network activity"""
        suspicious_connections = []
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED":
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name().lower()
                    if any(
                        keyword in proc_name for keyword in self.suspicious_keywords
                    ):
                        suspicious_connections.append(
                            {
                                "pid": conn.pid,
                                "name": proc_name,
                                "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                                "remote": f"{conn.raddr.ip}:{conn.raddr.port}"
                                if conn.raddr
                                else "N/A",
                            }
                        )
                except:
                    continue
        return suspicious_connections

    def check_running_processes(self):
        """Enhanced process checking with threat scoring"""
        flagged = []
        for proc in psutil.process_iter(
            ["pid", "name", "exe", "cmdline", "username", "create_time"]
        ):
            try:
                proc_info = proc.info
                threat_score = self.calculate_threat_score(proc_info)

                if threat_score >= 30:  # Threshold for suspicious
                    threat_level = (
                        "Critical"
                        if threat_score >= 70
                        else "High"
                        if threat_score >= 50
                        else "Medium"
                    )
                    proc_info["threat_score"] = threat_score
                    proc_info["threat_level"] = threat_level
                    proc_info["cmdline_str"] = " ".join(proc_info.get("cmdline", []))
                    flagged.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return sorted(flagged, key=lambda x: x["threat_score"], reverse=True)

    def check_input_devices(self):
        """Check for processes accessing input devices"""
        suspicious = []
        try:
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                try:
                    for file in proc.open_files():
                        if "/dev/input" in file.path or "/dev/uinput" in file.path:
                            suspicious.append(
                                {
                                    "pid": proc.info["pid"],
                                    "name": proc.info["name"],
                                    "device": file.path,
                                    "exe": proc.info["exe"],
                                }
                            )
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
        except:
            pass
        return suspicious


class ModernLinuxKeyloggerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Keylogger Detection and Termination System (Linux)")
        self.root.geometry("1920x1080")
        self.detector = LinuxKeyloggerDetector()
        self.monitoring_thread = None

        self.setup_styles()
        self.create_gui()

        self.suspicious_startup = []
        self.suspicious_procs = []
        self.suspicious_connections = []
        self.suspicious_services = []
        self.input_devices = []

    def setup_styles(self):
        """Setup modern color scheme and styles"""
        self.colors = {
            "bg": "#ffffff",
            "fg": "#2c3e50",
            "primary": "#3498db",
            "secondary": "#e74c3c",
            "success": "#27ae60",
            "warning": "#f39c12",
            "danger": "#e74c3c",
            "surface": "#f8f9fa",
            "surface_light": "#e9ecef",
            "accent": "#9b59b6",
        }

        style = ttk.Style()
        style.theme_use("clam")

        # Configure colors
        style.configure("TFrame", background=self.colors["bg"])
        style.configure(
            "TLabel",
            background=self.colors["bg"],
            foreground=self.colors["fg"],
            font=("Ubuntu", 10),
        )
        style.configure(
            "Title.TLabel",
            font=("Ubuntu", 16, "bold"),
            foreground=self.colors["primary"],
        )
        style.configure(
            "Header.TLabel",
            font=("Ubuntu", 11, "bold"),
            foreground=self.colors["primary"],
        )

        # Button styles
        style.configure(
            "Primary.TButton",
            background=self.colors["primary"],
            foreground="#ffffff",
            font=("Ubuntu", 10, "bold"),
            borderwidth=0,
            focuscolor="none",
            padding=10,
        )
        style.map("Primary.TButton", background=[("active", "#2980b9")])

        style.configure(
            "Danger.TButton",
            background=self.colors["danger"],
            foreground="#ffffff",
            font=("Ubuntu", 10, "bold"),
            borderwidth=0,
            padding=10,
        )
        style.map("Danger.TButton", background=[("active", "#c0392b")])

        # Notebook style
        style.configure("TNotebook", background=self.colors["bg"], borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=self.colors["surface"],
            foreground=self.colors["fg"],
            padding=[20, 10],
            font=("Ubuntu", 10, "bold"),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.colors["surface_light"])],
            foreground=[("selected", self.colors["primary"])],
        )

        # Treeview styles
        style.configure(
            "Treeview",
            background=self.colors["surface"],
            foreground=self.colors["fg"],
            fieldbackground=self.colors["surface"],
            borderwidth=0,
            font=("Ubuntu Mono", 9),
            rowheight=25,
        )
        style.configure(
            "Treeview.Heading",
            background=self.colors["surface_light"],
            foreground=self.colors["primary"],
            font=("Ubuntu", 10, "bold"),
            borderwidth=1,
            relief="flat",
        )
        style.map(
            "Treeview",
            background=[("selected", self.colors["primary"])],
            foreground=[("selected", "#ffffff")],
        )

        self.root.configure(bg=self.colors["bg"])

    def create_gui(self):
        """Create modern GUI layout"""
        # Header
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill="x", padx=20, pady=(20, 10))

        title_label = ttk.Label(
            header_frame,
            text="🛡️ Keylogger Detection and Termination System",
            style="Title.TLabel",
        )
        title_label.pack(side="left")

        self.status_label = ttk.Label(
            header_frame,
            text="● System Ready",
            foreground=self.colors["success"],
            font=("Ubuntu", 11, "bold"),
        )
        self.status_label.pack(side="right")

        # Main container with tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=10)

        # Tab 1: Processes
        proc_frame = ttk.Frame(self.notebook)
        self.notebook.add(proc_frame, text="  Suspicious Processes  ")
        self.create_process_tab(proc_frame)

        # Tab 2: Startup
        startup_frame = ttk.Frame(self.notebook)
        self.notebook.add(startup_frame, text="  Startup & Services  ")
        self.create_startup_tab(startup_frame)

        # Tab 3: Network
        network_frame = ttk.Frame(self.notebook)
        self.notebook.add(network_frame, text="  Network Activity  ")
        self.create_network_tab(network_frame)

        # Tab 4: Input Devices
        input_frame = ttk.Frame(self.notebook)
        self.notebook.add(input_frame, text="  Input Device Access  ")
        self.create_input_tab(input_frame)

        # Tab 5: Real-time Monitor
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="  Real-Time Monitor  ")
        self.create_monitor_tab(monitor_frame)

        # Control panel
        self.create_control_panel()

    def create_process_tab(self, parent):
        info_label = ttk.Label(
            parent,
            text="Detected processes with suspicious behavior patterns",
            style="Header.TLabel",
        )
        info_label.pack(anchor="w", padx=10, pady=5)

        columns = ("PID", "Name", "User", "Threat", "Score", "Command")
        self.proc_tree = ttk.Treeview(
            parent, columns=columns, show="headings", height=18
        )

        self.proc_tree.heading("PID", text="PID")
        self.proc_tree.heading("Name", text="Process")
        self.proc_tree.heading("User", text="User")
        self.proc_tree.heading("Threat", text="Threat")
        self.proc_tree.heading("Score", text="Score")
        self.proc_tree.heading("Command", text="Command Line")

        self.proc_tree.column("PID", width=70)
        self.proc_tree.column("Name", width=150)
        self.proc_tree.column("User", width=100)
        self.proc_tree.column("Threat", width=90)
        self.proc_tree.column("Score", width=70)
        self.proc_tree.column("Command", width=500)

        scrollbar = ttk.Scrollbar(
            parent, orient="vertical", command=self.proc_tree.yview
        )
        self.proc_tree.configure(yscrollcommand=scrollbar.set)

        self.proc_tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=5)
        scrollbar.pack(side="right", fill="y", padx=(0, 10), pady=5)

    def create_startup_tab(self, parent):
        info_label = ttk.Label(
            parent,
            text="Suspicious autostart entries and systemd services",
            style="Header.TLabel",
        )
        info_label.pack(anchor="w", padx=10, pady=5)

        columns = ("Type", "Name", "Status", "Path")
        self.startup_tree = ttk.Treeview(
            parent, columns=columns, show="headings", height=18
        )

        self.startup_tree.heading("Type", text="Type")
        self.startup_tree.heading("Name", text="Entry Name")
        self.startup_tree.heading("Status", text="Status")
        self.startup_tree.heading("Path", text="Path/Description")

        self.startup_tree.column("Type", width=120)
        self.startup_tree.column("Name", width=200)
        self.startup_tree.column("Status", width=100)
        self.startup_tree.column("Path", width=600)

        scrollbar = ttk.Scrollbar(
            parent, orient="vertical", command=self.startup_tree.yview
        )
        self.startup_tree.configure(yscrollcommand=scrollbar.set)

        self.startup_tree.pack(
            side="left", fill="both", expand=True, padx=(10, 0), pady=5
        )
        scrollbar.pack(side="right", fill="y", padx=(0, 10), pady=5)

    def create_network_tab(self, parent):
        info_label = ttk.Label(
            parent,
            text="Active network connections from suspicious processes",
            style="Header.TLabel",
        )
        info_label.pack(anchor="w", padx=10, pady=5)

        columns = ("PID", "Process", "Local", "Remote")
        self.network_tree = ttk.Treeview(
            parent, columns=columns, show="headings", height=18
        )

        self.network_tree.heading("PID", text="PID")
        self.network_tree.heading("Process", text="Process Name")
        self.network_tree.heading("Local", text="Local Address:Port")
        self.network_tree.heading("Remote", text="Remote Address:Port")

        self.network_tree.column("PID", width=80)
        self.network_tree.column("Process", width=250)
        self.network_tree.column("Local", width=300)
        self.network_tree.column("Remote", width=300)

        scrollbar = ttk.Scrollbar(
            parent, orient="vertical", command=self.network_tree.yview
        )
        self.network_tree.configure(yscrollcommand=scrollbar.set)

        self.network_tree.pack(
            side="left", fill="both", expand=True, padx=(10, 0), pady=5
        )
        scrollbar.pack(side="right", fill="y", padx=(0, 10), pady=5)

    def create_input_tab(self, parent):
        info_label = ttk.Label(
            parent,
            text="Processes accessing keyboard/input devices (/dev/input)",
            style="Header.TLabel",
        )
        info_label.pack(anchor="w", padx=10, pady=5)

        columns = ("PID", "Process", "Device", "Executable")
        self.input_tree = ttk.Treeview(
            parent, columns=columns, show="headings", height=18
        )

        self.input_tree.heading("PID", text="PID")
        self.input_tree.heading("Process", text="Process Name")
        self.input_tree.heading("Device", text="Device Path")
        self.input_tree.heading("Executable", text="Executable Path")

        self.input_tree.column("PID", width=80)
        self.input_tree.column("Process", width=200)
        self.input_tree.column("Device", width=250)
        self.input_tree.column("Executable", width=500)

        scrollbar = ttk.Scrollbar(
            parent, orient="vertical", command=self.input_tree.yview
        )
        self.input_tree.configure(yscrollcommand=scrollbar.set)

        self.input_tree.pack(
            side="left", fill="both", expand=True, padx=(10, 0), pady=5
        )
        scrollbar.pack(side="right", fill="y", padx=(0, 10), pady=5)

    def create_monitor_tab(self, parent):
        info_label = ttk.Label(
            parent,
            text="Real-time monitoring of suspicious system activity",
            style="Header.TLabel",
        )
        info_label.pack(anchor="w", padx=10, pady=5)

        self.monitor_text = tk.Text(
            parent,
            bg=self.colors["surface"],
            fg=self.colors["fg"],
            font=("Ubuntu Mono", 9),
            height=25,
            wrap="word",
            insertbackground=self.colors["primary"],
            relief="solid",
            borderwidth=1,
        )
        self.monitor_text.pack(fill="both", expand=True, padx=10, pady=5)

        scrollbar = ttk.Scrollbar(
            parent, orient="vertical", command=self.monitor_text.yview
        )
        self.monitor_text.configure(yscrollcommand=scrollbar.set)

        # Configure text tags for colored output
        self.monitor_text.tag_config("alert", foreground=self.colors["danger"])
        self.monitor_text.tag_config("warning", foreground=self.colors["warning"])
        self.monitor_text.tag_config("info", foreground=self.colors["primary"])
        self.monitor_text.tag_config("success", foreground=self.colors["success"])

    def create_control_panel(self):
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill="x", padx=20, pady=(0, 20))

        self.scan_btn = ttk.Button(
            control_frame,
            text="🔍 Full System Scan",
            command=self.full_scan,
            style="Primary.TButton",
        )
        self.scan_btn.pack(side="left", padx=5)

        self.terminate_btn = ttk.Button(
            control_frame,
            text="⚠️ Terminate Process",
            command=self.terminate_selected,
            style="Danger.TButton",
        )
        self.terminate_btn.pack(side="left", padx=5)

        self.monitor_btn = ttk.Button(
            control_frame,
            text="▶️ Start Monitoring",
            command=self.toggle_monitoring,
            style="Primary.TButton",
        )
        self.monitor_btn.pack(side="left", padx=5)

        self.save_btn = ttk.Button(
            control_frame,
            text="💾 Save Report",
            command=self.save_report,
            style="Primary.TButton",
        )
        self.save_btn.pack(side="left", padx=5)

        self.threat_label = ttk.Label(
            control_frame,
            text="Threats: 0",
            font=("Ubuntu", 12, "bold"),
            foreground=self.colors["success"],
        )
        self.threat_label.pack(side="right", padx=10)

    def full_scan(self):
        self.status_label.config(
            text="● Scanning System...", foreground=self.colors["warning"]
        )
        self.scan_btn.config(state="disabled")
        self.root.update()

        def scan_thread():
            # Clear previous results
            self.proc_tree.delete(*self.proc_tree.get_children())
            self.startup_tree.delete(*self.startup_tree.get_children())
            self.network_tree.delete(*self.network_tree.get_children())
            self.input_tree.delete(*self.input_tree.get_children())

            self.root.after(
                0,
                lambda: self.log_monitor(
                    "[SYSTEM] Starting full system scan...", "info"
                ),
            )

            # Scan processes
            self.root.after(
                0,
                lambda: self.log_monitor(
                    "[SCAN] Checking running processes...", "info"
                ),
            )
            self.suspicious_procs = self.detector.check_running_processes()
            for proc in self.suspicious_procs:
                self.proc_tree.insert(
                    "",
                    "end",
                    values=(
                        proc["pid"],
                        proc["name"],
                        proc.get("username", "N/A"),
                        proc["threat_level"],
                        f"{proc['threat_score']}%",
                        proc.get("cmdline_str", "N/A")[:100],
                    ),
                )

            # Scan startup
            self.root.after(
                0,
                lambda: self.log_monitor("[SCAN] Checking startup entries...", "info"),
            )
            self.suspicious_startup = self.detector.check_startup_entries()
            for entry in self.suspicious_startup:
                self.startup_tree.insert(
                    "",
                    "end",
                    values=("Autostart", entry["name"], entry["threat"], entry["path"]),
                )

            # Scan systemd services
            self.root.after(
                0,
                lambda: self.log_monitor("[SCAN] Checking systemd services...", "info"),
            )
            self.suspicious_services = self.detector.check_systemd_services()
            for service in self.suspicious_services:
                self.startup_tree.insert(
                    "",
                    "end",
                    values=(
                        "Service",
                        service["name"],
                        service["status"],
                        service["description"],
                    ),
                )

            # Scan network
            self.root.after(
                0,
                lambda: self.log_monitor(
                    "[SCAN] Checking network connections...", "info"
                ),
            )
            self.suspicious_connections = self.detector.check_network_connections()
            for conn in self.suspicious_connections:
                self.network_tree.insert(
                    "",
                    "end",
                    values=(conn["pid"], conn["name"], conn["local"], conn["remote"]),
                )

            # Scan input devices
            self.root.after(
                0,
                lambda: self.log_monitor(
                    "[SCAN] Checking input device access...", "info"
                ),
            )
            self.input_devices = self.detector.check_input_devices()
            for dev in self.input_devices:
                self.input_tree.insert(
                    "",
                    "end",
                    values=(
                        dev["pid"],
                        dev["name"],
                        dev["device"],
                        dev["exe"] or "N/A",
                    ),
                )

            total_threats = (
                len(self.suspicious_procs)
                + len(self.suspicious_startup)
                + len(self.suspicious_connections)
                + len(self.suspicious_services)
                + len(self.input_devices)
            )

            self.root.after(0, lambda: self.update_after_scan(total_threats))

        threading.Thread(target=scan_thread, daemon=True).start()

    def update_after_scan(self, total_threats):
        self.scan_btn.config(state="normal")
        if total_threats > 0:
            self.status_label.config(
                text="⚠️ Threats Detected!", foreground=self.colors["danger"]
            )
            self.threat_label.config(
                text=f"Threats: {total_threats}", foreground=self.colors["danger"]
            )
            self.log_monitor(
                f"[ALERT] Scan complete: {total_threats} potential threats found!",
                "alert",
            )
        else:
            self.status_label.config(
                text="✓ System Clean", foreground=self.colors["success"]
            )
            self.threat_label.config(
                text="Threats: 0", foreground=self.colors["success"]
            )
            self.log_monitor("[SUCCESS] Scan complete: No threats detected", "success")

    def terminate_selected(self):
        selected = self.proc_tree.selection()
        if not selected:
            messagebox.showinfo(
                "No Selection",
                "Please select a process to terminate from the Processes tab.",
            )
            return

        for item in selected:
            values = self.proc_tree.item(item)["values"]
            pid = values[0]
            name = values[1]

            if messagebox.askyesno(
                "Confirm Termination",
                f"Terminate process '{name}' (PID: {pid})?\n\n"
                "⚠️ Warning: Only terminate if you're certain it's malicious.\n"
                "This may require sudo privileges.",
            ):
                try:
                    proc = psutil.Process(pid)
                    proc.terminate()
                    proc.wait(timeout=3)
                    self.proc_tree.delete(item)
                    self.log_monitor(
                        f"[TERMINATED] Successfully killed PID {pid} ({name})",
                        "success",
                    )
                    messagebox.showinfo(
                        "Success", f"Process {pid} terminated successfully."
                    )
                except psutil.TimeoutExpired:
                    try:
                        proc.kill()
                        self.log_monitor(
                            f"[KILLED] Force killed PID {pid} ({name})", "warning"
                        )
                    except:
                        pass
                except PermissionError:
                    messagebox.showerror(
                        "Permission Denied",
                        f"Cannot terminate PID {pid}. Try running with sudo.",
                    )
                    self.log_monitor(
                        f"[ERROR] Permission denied to terminate PID {pid}", "alert"
                    )
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to terminate: {str(e)}")
                    self.log_monitor(
                        f"[ERROR] Failed to terminate PID {pid}: {str(e)}", "alert"
                    )

    def toggle_monitoring(self):
        if not self.detector.monitoring:
            self.detector.monitoring = True
            self.monitor_btn.config(text="⏸️ Stop Monitoring")
            self.monitoring_thread = threading.Thread(
                target=self.monitor_loop, daemon=True
            )
            self.monitoring_thread.start()
            self.log_monitor("[SYSTEM] Real-time monitoring started", "success")
        else:
            self.detector.monitoring = False
            self.monitor_btn.config(text="▶️ Start Monitoring")
            self.log_monitor("[SYSTEM] Real-time monitoring stopped", "warning")

    def monitor_loop(self):
        while self.detector.monitoring:
            procs = self.detector.check_running_processes()
            for proc in procs:
                if proc["threat_score"] >= 70:
                    msg = f"[ALERT] High threat: {proc['name']} (PID: {proc['pid']}, Score: {proc['threat_score']}%)"
                    self.root.after(0, lambda m=msg: self.log_monitor(m, "alert"))
            time.sleep(5)

    def log_monitor(self, message, tag="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.monitor_text.insert("end", f"[{timestamp}] {message}\n", tag)
        self.monitor_text.see("end")

    def save_report(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("Markdown Files", "*.md")],
        )

        if not file_path:
            return

        try:
            with open(file_path, "w") as f:
                f.write("=" * 90 + "\n")
                f.write("KEYLOGGER DETECTION REPORT\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"System: {os.uname().sysname} {os.uname().release}\n")
                f.write("=" * 90 + "\n\n")

                f.write("SUSPICIOUS PROCESSES:\n")
                f.write("-" * 90 + "\n")
                if self.suspicious_procs:
                    for proc in self.suspicious_procs:
                        f.write(
                            f"PID: {proc['pid']} | Name: {proc['name']} | User: {proc.get('username', 'N/A')}\n"
                        )
                        f.write(
                            f"Threat Level: {proc['threat_level']} | Score: {proc['threat_score']}%\n"
                        )
                        f.write(f"Executable: {proc['exe']}\n")
                        f.write(f"Command: {proc.get('cmdline_str', 'N/A')}\n\n")
                else:
                    f.write("No suspicious processes detected.\n\n")

                f.write("\nSTARTUP ENTRIES & SERVICES:\n")
                f.write("-" * 90 + "\n")
                if self.suspicious_startup or self.suspicious_services:
                    for entry in self.suspicious_startup:
                        f.write(f"Type: Autostart | Name: {entry['name']}\n")
                        f.write(f"Threat: {entry['threat']}\n")
                        f.write(f"Path: {entry['path']}\n")
                        f.write(f"Location: {entry['location']}\n\n")
                    for service in self.suspicious_services:
                        f.write(f"Type: Systemd Service | Name: {service['name']}\n")
                        f.write(f"Status: {service['status']}\n")
                        f.write(f"Description: {service['description']}\n\n")
                else:
                    f.write("No suspicious startup entries detected.\n\n")

                f.write("\nNETWORK CONNECTIONS:\n")
                f.write("-" * 90 + "\n")
                if self.suspicious_connections:
                    for conn in self.suspicious_connections:
                        f.write(f"PID: {conn['pid']} | Process: {conn['name']}\n")
                        f.write(
                            f"Local: {conn['local']} -> Remote: {conn['remote']}\n\n"
                        )
                else:
                    f.write("No suspicious network connections detected.\n\n")

                f.write("\nINPUT DEVICE ACCESS:\n")
                f.write("-" * 90 + "\n")
                if self.input_devices:
                    for dev in self.input_devices:
                        f.write(f"PID: {dev['pid']} | Process: {dev['name']}\n")
                        f.write(f"Device: {dev['device']}\n")
                        f.write(f"Executable: {dev['exe']}\n\n")
                else:
                    f.write("No suspicious input device access detected.\n\n")

                f.write("\n" + "=" * 90 + "\n")
                f.write("RECOMMENDATIONS:\n")
                f.write("-" * 90 + "\n")
                f.write(
                    "1. Review all flagged processes carefully before taking action\n"
                )
                f.write(
                    "2. Check /var/log/auth.log and /var/log/syslog for suspicious activity\n"
                )
                f.write("3. Verify all startup entries and disable unknown services\n")
                f.write("4. Monitor network connections for data exfiltration\n")
                f.write(
                    "5. Consider using AppArmor or SELinux for additional protection\n"
                )
                f.write("6. Keep your system and all packages up to date\n")
                f.write("7. Use 'sudo netstat -tulpn' to verify listening ports\n")
                f.write("8. Check for rootkits using: rkhunter --check\n")

            messagebox.showinfo("Success", f"Report saved to:\n{file_path}")
            self.log_monitor(f"[SUCCESS] Report saved to {file_path}", "success")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save report: {str(e)}")
            self.log_monitor(f"[ERROR] Failed to save report: {str(e)}", "alert")


if __name__ == "__main__":
    # Check if running on Linux
    if sys.platform != "linux":
        print("This tool is designed for Linux systems only.")
        sys.exit(1)

    root = tk.Tk()
    app = ModernLinuxKeyloggerGUI(root)

    # Welcome message
    app.log_monitor("=" * 60, "info")
    app.log_monitor("Keylogger Detection and Termination System (Linux) v2.0", "info")
    app.log_monitor("Protecting your system from unauthorized input monitoring", "info")
    app.log_monitor("=" * 60, "info")
    app.log_monitor(
        "[INFO] Ready to scan. Click 'Full System Scan' to begin.", "success"
    )

    root.mainloop()
