import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox, font, filedialog
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
import matplotlib.animation as animation
import matplotlib.pyplot as plt
from matplotlib import style
import threading
import queue
import time
import socket
from collections import deque
import pandas as pd
import numpy as np
from matplotlib.colors import LinearSegmentedColormap
# Try different import paths for network_monitor to handle both capitalization styles
try:
    from .network_monitor import SystemNetworkMonitor
except ImportError:
    try:
        from MacIDS.netmon.network_monitor import SystemNetworkMonitor
    except ImportError:
        from macids.netmon.network_monitor import SystemNetworkMonitor
import datetime
import json
import csv
from matplotlib import cm
from collections import defaultdict
import psutil
import ipaddress

style.use('ggplot')

class NetworkAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MacIDS Network Analyzer")
        self.root.geometry("1280x800")
        
        # Define available themes
        self.available_themes = {
            "Dark": {
                "bg": "#2E3440",
                "fg": "#ECEFF4",
                "accent": "#5E81AC",
                "button": "#3B4252",
                "alert": "#BF616A",
                "success": "#A3BE8C",
                "highlight": "#4C566A",
                "chart_bg": "#3B4252"
            },
            "Light": {
                "bg": "#ECEFF4", 
                "fg": "#2E3440",
                "accent": "#5E81AC",
                "button": "#D8DEE9",
                "alert": "#BF616A",
                "success": "#A3BE8C",
                "highlight": "#E5E9F0",
                "chart_bg": "#E5E9F0"
            },
            "Grey": {
                "bg": "#4C566A",
                "fg": "#ECEFF4",
                "accent": "#88C0D0",
                "button": "#3B4252",
                "alert": "#BF616A",
                "success": "#A3BE8C",
                "highlight": "#2E3440",
                "chart_bg": "#3B4252"
            }
        }
        
        # Current theme - default to Dark
        self.current_theme = "Dark"
        self.theme_colors = self.available_themes[self.current_theme]
        
        # Set theme
        self.style = ttk.Style()
        try:
            self.style.theme_use('clam')
        except:
            print("Could not set theme to 'clam', using default theme")
        
        # Custom colors
        self.apply_theme("Light")  # Start with light theme instead of dark theme
        
        # Check if running as admin/root
        self.is_admin = self.check_admin_privileges()
        if not self.is_admin:
            messagebox.showwarning("Root Required", 
                                 "Network Analyzer requires root privileges for full functionality.\nSome features may not work correctly.")
        
        # Create menu
        self.create_menu()
        
        # Create control buttons at top of window for better visibility
        self.control_frame = ttk.Frame(root)
        self.control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Add large, colorful buttons
        self.start_button = ttk.Button(self.control_frame, text="START MONITORING", 
                                     command=self.start_monitoring,
                                     style="StartButton.TButton")
        self.start_button.pack(side=tk.LEFT, padx=20, pady=5)
        
        self.stop_button = ttk.Button(self.control_frame, text="STOP MONITORING", 
                                    command=self.stop_monitoring, 
                                    state=tk.DISABLED,
                                    style="StopButton.TButton")
        self.stop_button.pack(side=tk.LEFT, padx=20, pady=5)
        
        self.export_button = ttk.Button(self.control_frame, text="EXPORT DATA", 
                                      command=self.export_data)
        self.export_button.pack(side=tk.LEFT, padx=20, pady=5)
        
        self.status_var = tk.StringVar(value="Status: Ready to Monitor")
        self.status_label = ttk.Label(self.control_frame, textvariable=self.status_var, font=('Arial', 12))
        self.status_label.pack(side=tk.RIGHT, padx=20, pady=5)
        
        # Create main frame
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.overview_tab = ttk.Frame(self.notebook)
        self.connections_tab = ttk.Frame(self.notebook)
        self.map_tab = ttk.Frame(self.notebook)  # New map tab for geolocation
        self.ports_tab = ttk.Frame(self.notebook)
        self.applications_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)  # New settings tab
        
        self.notebook.add(self.overview_tab, text="Overview")
        self.notebook.add(self.connections_tab, text="Connections")
        self.notebook.add(self.map_tab, text="World Map")  # Add map tab to notebook
        self.notebook.add(self.ports_tab, text="Ports")
        self.notebook.add(self.applications_tab, text="Applications")
        self.notebook.add(self.settings_tab, text="Settings")  # Add settings tab
        
        # Set up tabs
        self.setup_overview_tab()
        self.setup_connections_tab()
        self.setup_map_tab()  # Set up the new map tab
        self.setup_ports_tab()
        self.setup_applications_tab()
        self.setup_settings_tab()  # Set up the settings tab
        
        # Initialize data structures
        self.time_data = deque(maxlen=60)
        self.packets_data = deque(maxlen=60)
        self.bytes_data = deque(maxlen=60)
        self.protocol_data = {}
        self.connection_data = []
        self.port_data = []
        self.application_data = []
        self.domain_data = []
        self.geo_data = {'connections': [], 'countries': {}}  # Store geolocation data
        
        # Initialize monitor
        self.monitor = None
        self.monitor_thread = None
        self.queue = queue.Queue()
        self.running = False
        
        # Map animation
        self.map_animation = None
        # Overview animation
        self.overview_animation = None
        
        # Set up close event handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Add a note about starting monitoring
        note_frame = ttk.Frame(root)
        note_frame.pack(fill=tk.X, padx=10, pady=5)
        note_label = ttk.Label(note_frame, 
                              text="Note: Click the 'START MONITORING' button above to begin capturing network traffic.", 
                              font=('Arial', 10, 'italic'))
        note_label.pack(pady=5)
    
    def create_menu(self):
        """Create application menu"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export Connections", command=lambda: self.export_data("connections"))
        file_menu.add_command(label="Export Applications", command=lambda: self.export_data("applications"))
        file_menu.add_command(label="Export Geo Data", command=lambda: self.export_data("geo"))
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Overview", command=lambda: self.notebook.select(0))
        view_menu.add_command(label="Connections", command=lambda: self.notebook.select(1))
        view_menu.add_command(label="World Map", command=lambda: self.notebook.select(2))
        view_menu.add_command(label="Ports", command=lambda: self.notebook.select(3))
        view_menu.add_command(label="Applications", command=lambda: self.notebook.select(4))
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Traffic Recording", command=self.record_traffic)
        tools_menu.add_command(label="Connection Blocking", command=self.block_connection)
        tools_menu.add_separator()
        tools_menu.add_command(label="Clear Statistics", command=self.clear_stats)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def check_admin_privileges(self):
        """Check if running with root privileges (for macOS)"""
        try:
            return os.geteuid() == 0
        except:
            return False
    
    def apply_theme(self, theme_name):
        """Apply the selected theme to the GUI"""
        if theme_name not in self.available_themes:
            print(f"Theme {theme_name} not found. Using default theme.")
            theme_name = "Light"
        
        self.current_theme = theme_name
        self.theme_colors = self.available_themes[theme_name]
        
        # Apply colors to root window
        self.root.configure(bg=self.theme_colors["bg"])
        
        # Configure ttk styles
        self.style.configure("TFrame", background=self.theme_colors["bg"])
        self.style.configure("TLabel", background=self.theme_colors["bg"], foreground=self.theme_colors["fg"])
        self.style.configure("TButton", background=self.theme_colors["button"], foreground=self.theme_colors["fg"])
        self.style.configure("TNotebook", background=self.theme_colors["bg"])
        self.style.configure("TNotebook.Tab", background=self.theme_colors["button"], foreground=self.theme_colors["fg"])
        
        # Configure custom button styles
        self.style.configure("StartButton.TButton", 
                           background=self.theme_colors["success"],
                           foreground=self.theme_colors["fg"])
        self.style.configure("StopButton.TButton",
                           background=self.theme_colors["alert"],
                           foreground=self.theme_colors["fg"])
        
        # Update matplotlib style
        plt.style.use('ggplot')
        plt.rcParams['figure.facecolor'] = self.theme_colors["chart_bg"]
        plt.rcParams['axes.facecolor'] = self.theme_colors["chart_bg"]
        plt.rcParams['text.color'] = self.theme_colors["fg"]
        plt.rcParams['axes.labelcolor'] = self.theme_colors["fg"]
        plt.rcParams['xtick.color'] = self.theme_colors["fg"]
        plt.rcParams['ytick.color'] = self.theme_colors["fg"]
        
        # Update any existing plots
        if hasattr(self, 'overview_animation') and self.overview_animation:
            self.overview_animation.event_source.stop()
            self.setup_overview_tab()
        if hasattr(self, 'map_animation') and self.map_animation:
            self.map_animation.event_source.stop()
            self.setup_map_tab()
    
    def on_close(self):
        """Handle window close event"""
        try:
            # Stop monitoring if running
            if self.running:
                self.stop_monitoring()
            
            # Destroy the window
            self.root.destroy()
        except Exception as e:
            print(f"Error during shutdown: {e}")
            # Force destroy the window
            self.root.destroy()
    
    def start_monitoring(self):
        """Start network monitoring"""
        try:
            # Check if already running
            if self.monitor and self.running:
                messagebox.showinfo("Already Running", "Network monitoring is already active.")
                return
            
            # Update status
            self.status_var.set("Status: Starting Monitoring...")
            
            # Create SystemNetworkMonitor instance
            if not self.monitor:
                try:
                    from .network_monitor import SystemNetworkMonitor
                except ImportError:
                    try:
                        from MacIDS.netmon.network_monitor import SystemNetworkMonitor
                    except ImportError:
                        from macids.netmon.network_monitor import SystemNetworkMonitor
                self.monitor = SystemNetworkMonitor()
            
            # Start capture
            if self.monitor.start_capture():
                self.running = True
                
                # Update UI
                self.start_button.configure(state=tk.DISABLED)
                self.stop_button.configure(state=tk.NORMAL)
                self.status_var.set("Status: Monitoring")
                
                # Start data collection thread
                self.monitor_thread = threading.Thread(target=self.collect_data)
                self.monitor_thread.daemon = True
                self.monitor_thread.start()
                
                # Start UI update timer
                self.root.after(1000, self.process_queue)
                
                # Start animations
                self.overview_animation = animation.FuncAnimation(
                    self.fig, self.update_graphs, interval=1000, blit=False)
                
                self.map_animation = animation.FuncAnimation(
                    self.map_fig, self.update_map, interval=5000, blit=False)
            else:
                messagebox.showerror("Error", "Failed to start network monitoring.\nMake sure you are running with root privileges.")
                self.status_var.set("Status: Failed to Start")
        except Exception as e:
            messagebox.showerror("Error", f"Error starting monitoring: {str(e)}")
            self.status_var.set("Status: Error")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
MacIDS Network Analyzer

Version: 1.0
Copyright © 2023 MacIDS Team

A network traffic analyzer and intrusion detection system for macOS.
This software provides real-time network monitoring, visualization,
and security analysis.

Running with root privileges: {0}
        """.format("Yes" if self.is_admin else "No")
        
        messagebox.showinfo("About MacIDS", about_text)

def main():
    """Main function to start the application"""
    try:
        # Create Tkinter root window
        root = tk.Tk()
        
        # Create the GUI application
        app = NetworkAnalyzerGUI(root)
        
        # Start the Tkinter event loop
        root.mainloop()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 