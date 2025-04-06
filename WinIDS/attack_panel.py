#!/usr/bin/env python
"""
WinIDS Attack Panel

Graphical user interface for launching test attacks against the IDS system.
"""

import os
import sys
import json
import socket
import logging
import argparse
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("WinIDS_attack_panel.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("WinIDS-AttackPanel")

# Attack types
ATTACK_TYPES = ["dos", "probe", "r2l", "u2r"]

class AttackPanel:
    """Attack Panel for WinIDS - Used to generate test attacks against the IDS system."""
    
    def __init__(self, bridge_host="localhost", bridge_port=5000, dark_mode=True):
        """Initialize the attack panel."""
        self.bridge_host = bridge_host
        self.bridge_port = bridge_port
        self.dark_mode = dark_mode
        self.bridge_socket = None
        self.heartbeat_thread = None
        self.connected = False
        
        # Create root window
        self.root = tk.Tk()
        self.root.title("WinIDS - Attack Panel")
        self.root.geometry("500x600")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Create status variable
        self.status_var = tk.StringVar(value="Ready")
        
        # Set theme colors
        self._setup_theme()
        
        # Create widgets
        self._create_widgets()
    
    def _setup_theme(self):
        """Set up theme colors."""
        if self.dark_mode:
            self.bg_color = "#2d2d2d"
            self.fg_color = "#f0f0f0"
            self.entry_bg = "#3d3d3d"
            self.button_bg = "#bf2c34"
            self.button_fg = "#ffffff"
        else:
            self.bg_color = "#f5f5f5"
            self.fg_color = "#333333"
            self.entry_bg = "#ffffff"
            self.button_bg = "#e74c3c"
            self.button_fg = "#ffffff"
            
        # Apply colors
        self.root.configure(bg=self.bg_color)
        
        # Create styles
        self.style = ttk.Style()
        self.style.configure("TFrame", background=self.bg_color)
        self.style.configure("TLabel", background=self.bg_color, foreground=self.fg_color)
        self.style.configure("TButton", background=self.button_bg, foreground=self.button_fg)
    
    def _create_widgets(self):
        """Create the panel widgets."""
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(main_frame, text="WinIDS Attack Panel", font=("Helvetica", 16, "bold"))
        title_label.pack(pady=(0, 10))
        
        # Connection frame
        connection_frame = ttk.Frame(main_frame)
        connection_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(connection_frame, text="Bridge Host:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.host_entry = ttk.Entry(connection_frame)
        self.host_entry.insert(0, self.bridge_host)
        self.host_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=2)
        
        ttk.Label(connection_frame, text="Bridge Port:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.port_entry = ttk.Entry(connection_frame)
        self.port_entry.insert(0, str(self.bridge_port))
        self.port_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=2)
        
        connection_frame.columnconfigure(1, weight=1)
        
        # Connect button
        self.connect_button = ttk.Button(main_frame, text="Connect to Bridge", command=self.connect_to_bridge)
        self.connect_button.pack(fill=tk.X, pady=5)
        
        # Attack settings frame
        attack_frame = ttk.LabelFrame(main_frame, text="Attack Settings")
        attack_frame.pack(fill=tk.X, pady=10)
        
        # Attack type
        ttk.Label(attack_frame, text="Attack Type:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.attack_type = tk.StringVar(value="dos")
        
        attack_type_frame = ttk.Frame(attack_frame)
        attack_type_frame.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        
        for i, attack in enumerate(ATTACK_TYPES):
            rb = ttk.Radiobutton(attack_type_frame, text=attack.upper(), value=attack, variable=self.attack_type)
            rb.pack(side=tk.LEFT, padx=5)
        
        # Attack intensity
        ttk.Label(attack_frame, text="Intensity:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        intensity_frame = ttk.Frame(attack_frame)
        intensity_frame.grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        
        self.intensity_var = tk.DoubleVar(value=0.5)
        self.intensity_scale = ttk.Scale(intensity_frame, from_=0.1, to=1.0, 
                                          orient=tk.HORIZONTAL, variable=self.intensity_var)
        self.intensity_scale.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        intensity_label = ttk.Label(intensity_frame, text="0.5")
        intensity_label.pack(side=tk.RIGHT, padx=5)
        
        def update_intensity_label(*args):
            intensity_label.config(text=f"{self.intensity_var.get():.1f}")
        
        self.intensity_var.trace("w", update_intensity_label)
        
        # Duration
        ttk.Label(attack_frame, text="Duration (s):").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.duration_var = tk.IntVar(value=10)
        duration_frame = ttk.Frame(attack_frame)
        duration_frame.grid(row=2, column=1, sticky="ew", padx=5, pady=5)
        
        durations = [5, 10, 30, 60, 120]
        for i, dur in enumerate(durations):
            rb = ttk.Radiobutton(duration_frame, text=str(dur), value=dur, variable=self.duration_var)
            rb.pack(side=tk.LEFT, padx=5)
        
        attack_frame.columnconfigure(1, weight=1)
        
        # Launch attack button
        self.attack_button = ttk.Button(main_frame, text="Launch Attack", 
                                          command=self.launch_attack)
        self.attack_button.pack(fill=tk.X, pady=10)
        self.attack_button.config(state=tk.DISABLED)
        
        # Log frame
        log_frame = ttk.LabelFrame(main_frame, text="Command Log")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.config(bg=self.entry_bg, fg=self.fg_color)
        
        # Status bar
        status_bar = ttk.Frame(self.root)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        status_label = ttk.Label(status_bar, textvariable=self.status_var, padding=(5, 2))
        status_label.pack(side=tk.LEFT)
        
        self.connection_status = ttk.Label(status_bar, text="Disconnected", padding=(5, 2))
        self.connection_status.pack(side=tk.RIGHT)
    
    def log_message(self, message, level="INFO"):
        """Add message to the log with timestamp."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        
        # Log to logger as well
        if level == "INFO":
            logger.info(message)
        elif level == "ERROR":
            logger.error(message)
        elif level == "WARNING":
            logger.warning(message)
    
    def connect_to_bridge(self):
        """Connect to the IDS Bridge."""
        if self.connected:
            self.disconnect_from_bridge()
            return
        
        try:
            # Get host and port from entries
            host = self.host_entry.get().strip()
            port = int(self.port_entry.get().strip())
            
            # Create socket
            self.bridge_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.bridge_socket.settimeout(5)
            self.bridge_socket.connect((host, port))
            
            # Update state
            self.connected = True
            self.connection_status.config(text="Connected")
            self.connect_button.config(text="Disconnect")
            self.attack_button.config(state=tk.NORMAL)
            
            # Log connection
            self.log_message(f"Connected to IDS Bridge at {host}:{port}")
            self.status_var.set(f"Connected to IDS Bridge")
            
            # Start heartbeat thread
            self.heartbeat_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
            self.heartbeat_thread.start()
            
        except Exception as e:
            self.log_message(f"Failed to connect to IDS Bridge: {str(e)}", "ERROR")
            self.status_var.set("Connection failed")
            if self.bridge_socket:
                self.bridge_socket.close()
                self.bridge_socket = None
    
    def disconnect_from_bridge(self):
        """Disconnect from the IDS Bridge."""
        if self.bridge_socket:
            try:
                self.bridge_socket.close()
            except:
                pass
            
        self.bridge_socket = None
        self.connected = False
        self.connection_status.config(text="Disconnected")
        self.connect_button.config(text="Connect to Bridge")
        self.attack_button.config(state=tk.DISABLED)
        self.log_message("Disconnected from IDS Bridge")
        self.status_var.set("Disconnected")
    
    def heartbeat_loop(self):
        """Send periodic heartbeat messages to keep the connection alive."""
        while self.connected and self.bridge_socket:
            try:
                # Send heartbeat every 10 seconds
                message = json.dumps({
                    "type": "heartbeat",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                self.bridge_socket.sendall((message + "\n").encode())
                threading.Event().wait(10)  # Sleep for 10 seconds
            except:
                if self.connected:
                    # Connection lost
                    self.root.after(0, self.handle_disconnect)
                break
    
    def handle_disconnect(self):
        """Handle disconnection in the main thread."""
        self.disconnect_from_bridge()
        messagebox.showwarning("Connection Lost", "Connection to the IDS Bridge was lost.")
    
    def launch_attack(self):
        """Launch an attack with the selected parameters."""
        if not self.connected or not self.bridge_socket:
            messagebox.showerror("Error", "Not connected to IDS Bridge")
            return
        
        try:
            # Get attack parameters
            attack_type = self.attack_type.get()
            intensity = self.intensity_var.get()
            duration = self.duration_var.get()
            
            # Create attack command
            attack_cmd = {
                "type": "attack",
                "attack_type": attack_type,
                "intensity": intensity,
                "duration": duration,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # Send command to bridge
            self.bridge_socket.sendall((json.dumps(attack_cmd) + "\n").encode())
            
            # Log attack command
            self.log_message(f"Launched {attack_type.upper()} attack (intensity: {intensity:.1f}, duration: {duration}s)")
            self.status_var.set(f"Attack launched: {attack_type.upper()}")
            
            # Get response from bridge
            try:
                self.bridge_socket.settimeout(5)
                response = self.bridge_socket.recv(4096)
                if response:
                    try:
                        resp_data = json.loads(response.decode().strip())
                        if "status" in resp_data:
                            status = resp_data["status"]
                            message = resp_data.get("message", "")
                            self.log_message(f"Bridge response: {status} - {message}")
                    except:
                        self.log_message(f"Received response: {response.decode().strip()}")
            except socket.timeout:
                pass
            
        except Exception as e:
            self.log_message(f"Error launching attack: {str(e)}", "ERROR")
            self.status_var.set("Error launching attack")
    
    def on_close(self):
        """Handle window close event."""
        if self.connected:
            self.disconnect_from_bridge()
            
        self.root.destroy()
        
    def run(self):
        """Run the attack panel."""
        self.root.mainloop()

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="WinIDS Attack Panel")
    
    parser.add_argument("--bridge-host", type=str, default="localhost",
                      help="IDS Bridge host")
    parser.add_argument("--bridge-port", type=int, default=5000,
                      help="IDS Bridge port")
    parser.add_argument("--light-mode", action="store_true",
                      help="Use light mode theme (default is dark mode)")
    
    return parser.parse_args()

def main():
    """Main entry point."""
    # Parse command line arguments
    args = parse_args()
    
    # Create and run attack panel
    panel = AttackPanel(
        bridge_host=args.bridge_host,
        bridge_port=args.bridge_port,
        dark_mode=not args.light_mode
    )
    panel.run()
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 