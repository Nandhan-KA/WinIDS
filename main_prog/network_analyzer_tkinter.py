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
import ctypes
from collections import deque
import pandas as pd
import numpy as np
from matplotlib.colors import LinearSegmentedColormap
from network_monitor import SystemNetworkMonitor
import datetime
import json
import csv
from matplotlib import cm
from collections import defaultdict

style.use('ggplot')

class NetworkAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("WinIDS Network Analyzer")
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
        self.apply_theme("Dark")  # Start with dark theme
        
        # Check if running as admin
        self.is_admin = self.check_admin_privileges()
        if not self.is_admin:
            messagebox.showwarning("Admin Required", 
                                 "Network Analyzer requires administrator privileges for full functionality.\nSome features may not work correctly.")
        
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
        """Check if running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    
    def setup_overview_tab(self):
        # Create frames
        stats_frame = ttk.Frame(self.overview_tab)
        stats_frame.pack(side=tk.TOP, fill=tk.X, pady=5)
        
        graph_frame = ttk.Frame(self.overview_tab)
        graph_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, pady=5)
        
        # Create labels for stats
        self.stats_frame = ttk.LabelFrame(stats_frame, text="Network Statistics")
        self.stats_frame.pack(fill=tk.X, expand=True, padx=5, pady=5)
        
        self.total_packets_var = tk.StringVar(value="Total Packets: 0")
        self.total_traffic_var = tk.StringVar(value="Total Traffic: 0.00 MB")
        self.packet_rate_var = tk.StringVar(value="Packet Rate: 0 pps")
        self.bandwidth_var = tk.StringVar(value="Bandwidth: 0.00 Mbps")
        
        ttk.Label(self.stats_frame, textvariable=self.total_packets_var).pack(side=tk.LEFT, padx=10, pady=5)
        ttk.Label(self.stats_frame, textvariable=self.total_traffic_var).pack(side=tk.LEFT, padx=10, pady=5)
        ttk.Label(self.stats_frame, textvariable=self.packet_rate_var).pack(side=tk.LEFT, padx=10, pady=5)
        ttk.Label(self.stats_frame, textvariable=self.bandwidth_var).pack(side=tk.LEFT, padx=10, pady=5)
        
        # Create traffic graph (2x2 grid)
        self.fig = Figure(figsize=(12, 9), dpi=100, facecolor='#2E3440')
        
        # Packet Rate
        self.ax1 = self.fig.add_subplot(221)
        self.ax1.set_facecolor('#3B4252')
        self.ax1.set_title('Packet Rate (pps)', color='#ECEFF4')
        self.ax1.set_xlabel('Time (s)', color='#ECEFF4')
        self.ax1.set_ylabel('Packets/s', color='#ECEFF4')
        self.ax1.tick_params(colors='#ECEFF4')
        self.ax1.grid(True, alpha=0.3)
        
        # Bandwidth Usage
        self.ax2 = self.fig.add_subplot(222)
        self.ax2.set_facecolor('#3B4252')
        self.ax2.set_title('Bandwidth Usage (Mbps)', color='#ECEFF4')
        self.ax2.set_xlabel('Time (s)', color='#ECEFF4')
        self.ax2.set_ylabel('Mbps', color='#ECEFF4')
        self.ax2.tick_params(colors='#ECEFF4')
        self.ax2.grid(True, alpha=0.3)
        
        # Protocol Distribution
        self.ax3 = self.fig.add_subplot(223)
        self.ax3.set_facecolor('#3B4252')
        self.ax3.set_title('Protocol Distribution', color='#ECEFF4')
        self.ax3.tick_params(colors='#ECEFF4')
        
        # Application Bandwidth
        self.ax4 = self.fig.add_subplot(224)
        self.ax4.set_facecolor('#3B4252')
        self.ax4.set_title('Top Applications Bandwidth', color='#ECEFF4')
        self.ax4.tick_params(colors='#ECEFF4')
        
        self.fig.tight_layout(pad=3.0)
        
        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.fig, graph_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Add toolbar
        self.toolbar = NavigationToolbar2Tk(self.canvas, graph_frame)
        self.toolbar.update()
    
    def setup_connections_tab(self):
        # Create and configure connections treeview
        columns = ("Source", "Destination", "Protocol", "Packets", "Application", "Website")
        self.connections_tree = ttk.Treeview(self.connections_tab, columns=columns, show='headings')
        
        # Define column headings
        for col in columns:
            self.connections_tree.heading(col, text=col, command=lambda c=col: self.sort_treeview(self.connections_tree, c, False))
            self.connections_tree.column(col, width=100)
        
        # Set column widths
        self.connections_tree.column("Source", width=150)
        self.connections_tree.column("Destination", width=150)
        self.connections_tree.column("Protocol", width=80)
        self.connections_tree.column("Packets", width=80)
        self.connections_tree.column("Application", width=150)
        self.connections_tree.column("Website", width=200)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.connections_tab, orient=tk.VERTICAL, command=self.connections_tree.yview)
        self.connections_tree.configure(yscroll=scrollbar.set)
        
        # Pack widgets
        self.connections_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_map_tab(self):
        """Set up the map tab for geolocation visualization"""
        # Create frames
        control_frame = ttk.Frame(self.map_tab)
        control_frame.pack(side=tk.TOP, fill=tk.X, pady=5)
        
        map_frame = ttk.Frame(self.map_tab)
        map_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, pady=5)
        
        # Add controls
        ttk.Label(control_frame, text="Country Traffic:").pack(side=tk.LEFT, padx=10)
        
        # Create the world map figure
        self.map_fig = Figure(figsize=(12, 8), dpi=100, facecolor='#2E3440')
        self.map_ax = self.map_fig.add_subplot(111)
        self.map_ax.set_facecolor('#3B4252')
        
        # Create canvas for the map
        self.map_canvas = FigureCanvasTkAgg(self.map_fig, map_frame)
        self.map_canvas.draw()
        self.map_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Add toolbar
        self.map_toolbar = NavigationToolbar2Tk(self.map_canvas, map_frame)
        self.map_toolbar.update()
        
        # Initial map drawing
        self.draw_world_map([])
    
    def setup_ports_tab(self):
        # Create and configure ports treeview
        columns = ("Port", "Service", "Count", "Top Application")
        self.ports_tree = ttk.Treeview(self.ports_tab, columns=columns, show='headings')
        
        # Define column headings
        for col in columns:
            self.ports_tree.heading(col, text=col, command=lambda c=col: self.sort_treeview(self.ports_tree, c, False))
            self.ports_tree.column(col, width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.ports_tab, orient=tk.VERTICAL, command=self.ports_tree.yview)
        self.ports_tree.configure(yscroll=scrollbar.set)
        
        # Pack widgets
        self.ports_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_applications_tab(self):
        # Create frames
        app_frame = ttk.Frame(self.applications_tab)
        app_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, pady=5)
        
        domains_frame = ttk.Frame(self.applications_tab)
        domains_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, pady=5)
        
        # Application treeview
        ttk.Label(app_frame, text="Applications Network Usage").pack(anchor=tk.W, padx=5, pady=5)
        
        app_columns = ("Application", "Bytes", "Connections", "Domains")
        self.apps_tree = ttk.Treeview(app_frame, columns=app_columns, show='headings')
        
        # Define column headings
        for col in app_columns:
            self.apps_tree.heading(col, text=col, command=lambda c=col: self.sort_treeview(self.apps_tree, c, False))
            self.apps_tree.column(col, width=100)
        
        # Set column widths
        self.apps_tree.column("Application", width=200)
        self.apps_tree.column("Bytes", width=100)
        self.apps_tree.column("Connections", width=100)
        self.apps_tree.column("Domains", width=400)
        
        # Add scrollbar
        app_scrollbar = ttk.Scrollbar(app_frame, orient=tk.VERTICAL, command=self.apps_tree.yview)
        self.apps_tree.configure(yscroll=app_scrollbar.set)
        
        # Pack widgets
        self.apps_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        app_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Domain treeview
        ttk.Label(domains_frame, text="Websites/Domains Accessed").pack(anchor=tk.W, padx=5, pady=5)
        
        domain_columns = ("Domain", "Hits", "Applications")
        self.domain_tree = ttk.Treeview(domains_frame, columns=domain_columns, show='headings')
        
        # Define column headings
        for col in domain_columns:
            self.domain_tree.heading(col, text=col, command=lambda c=col: self.sort_treeview(self.domain_tree, c, False))
            self.domain_tree.column(col, width=100)
        
        # Set column widths
        self.domain_tree.column("Domain", width=300)
        self.domain_tree.column("Hits", width=100)
        self.domain_tree.column("Applications", width=300)
        
        # Add scrollbar
        domain_scrollbar = ttk.Scrollbar(domains_frame, orient=tk.VERTICAL, command=self.domain_tree.yview)
        self.domain_tree.configure(yscroll=domain_scrollbar.set)
        
        # Pack widgets
        self.domain_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        domain_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_settings_tab(self):
        """Set up the settings tab"""
        settings_frame = ttk.Frame(self.settings_tab)
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Theme selection
        theme_frame = ttk.LabelFrame(settings_frame, text="Application Theme")
        theme_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Theme selection variable
        self.theme_var = tk.StringVar(value=self.current_theme)
        
        # Theme radio buttons
        theme_options = list(self.available_themes.keys())
        for i, theme in enumerate(theme_options):
            theme_rb = ttk.Radiobutton(
                theme_frame, 
                text=theme,
                value=theme,
                variable=self.theme_var,
                command=lambda: self.apply_theme(self.theme_var.get())
            )
            theme_rb.pack(anchor=tk.W, padx=20, pady=5)
        
        # Theme preview 
        preview_frame = ttk.LabelFrame(settings_frame, text="Theme Preview")
        preview_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Sample elements in the preview
        ttk.Label(preview_frame, text="Sample text").pack(anchor=tk.W, padx=10, pady=5)
        ttk.Button(preview_frame, text="Sample Button").pack(anchor=tk.W, padx=10, pady=5)
        
        # Advanced settings
        advanced_frame = ttk.LabelFrame(settings_frame, text="Advanced Settings")
        advanced_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Update interval
        interval_frame = ttk.Frame(advanced_frame)
        interval_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(interval_frame, text="Update Interval (seconds):").pack(side=tk.LEFT, padx=5)
        
        self.update_interval = tk.StringVar(value="1")
        interval_entry = ttk.Entry(interval_frame, textvariable=self.update_interval, width=5)
        interval_entry.pack(side=tk.LEFT, padx=5)
        
        # Map update interval
        map_interval_frame = ttk.Frame(advanced_frame)
        map_interval_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(map_interval_frame, text="Map Update Interval (seconds):").pack(side=tk.LEFT, padx=5)
        
        self.map_update_interval = tk.StringVar(value="5")
        map_interval_entry = ttk.Entry(map_interval_frame, textvariable=self.map_update_interval, width=5)
        map_interval_entry.pack(side=tk.LEFT, padx=5)
        
        # Save settings button
        save_button = ttk.Button(settings_frame, text="Apply Settings", command=self.save_settings)
        save_button.pack(anchor=tk.E, padx=10, pady=10)

    def save_settings(self):
        """Save and apply settings"""
        try:
            # Apply theme
            self.apply_theme(self.theme_var.get())
            
            # Apply update intervals
            try:
                update_interval = float(self.update_interval.get())
                map_update_interval = float(self.map_update_interval.get())
                
                if update_interval > 0 and map_update_interval > 0:
                    # These will be used on next start
                    messagebox.showinfo("Settings Applied", "Settings have been applied. Some changes will take effect on restart.")
                else:
                    messagebox.showerror("Invalid Value", "Intervals must be positive numbers.")
            except ValueError:
                messagebox.showerror("Invalid Value", "Intervals must be numeric values.")
        except Exception as e:
            messagebox.showerror("Settings Error", f"Error applying settings: {e}")

    def draw_world_map(self, connections):
        """Draw the world map with connection lines"""
        self.map_ax.clear()
        self.map_ax.set_facecolor(self.theme_colors["chart_bg"])
        self.map_ax.set_title('Global Network Connections', color=self.theme_colors["fg"], fontsize=14)
        
        try:
            # Load world map
            # We'll use a simplified approach with just plotting points and lines
            self.map_ax.set_xlim([-180, 180])
            self.map_ax.set_ylim([-90, 90])
            self.map_ax.grid(True, alpha=0.3)
            
            # Create country hit counts for sizing points
            country_counts = {}
            country_locations = {}
            
            # If we have connections with geo data, use them for visualization
            if connections:
                # Track traffic by country
                for conn in connections:
                    # Add country to counts
                    src_country = conn.get('src_country', 'Unknown')
                    dst_country = conn.get('dst_country', 'Unknown')
                    
                    src_lat = conn.get('src_lat', 0)
                    src_lon = conn.get('src_lon', 0)
                    dst_lat = conn.get('dst_lat', 0)
                    dst_lon = conn.get('dst_lon', 0)
                    
                    if src_country not in country_counts and src_lat != 0 and src_lon != 0:
                        country_counts[src_country] = 0
                        country_locations[src_country] = (src_lat, src_lon)
                    
                    if dst_country not in country_counts and dst_lat != 0 and dst_lon != 0:
                        country_counts[dst_country] = 0
                        country_locations[dst_country] = (dst_lat, dst_lon)
                    
                    if dst_country in country_counts:
                        country_counts[dst_country] += 1
                    
                    # Draw line from source to destination (if both have valid locations)
                    if src_lat != 0 and src_lon != 0 and dst_lat != 0 and dst_lon != 0:
                        self.map_ax.plot([src_lon, dst_lon], 
                                        [src_lat, dst_lat], 
                                        'c-', alpha=0.1, linewidth=0.5)
            
            # If we don't have valid connections, always use country statistics
            # Even if connections were provided but had no valid coordinates
            if not country_counts and hasattr(self, 'geo_data'):
                # First try to use country data directly
                if 'countries' in self.geo_data and self.geo_data['countries']:
                    # Use the top countries data
                    top_countries = sorted(self.geo_data['countries'].items(), 
                                        key=lambda x: x[1], reverse=True)[:15]
                    
                    # Need to map countries to coordinates
                    default_coords = {
                        "United States": (37.0902, -95.7129),
                        "Russia": (61.5240, 105.3188),
                        "China": (35.8617, 104.1954),
                        "India": (20.5937, 78.9629),
                        "Japan": (36.2048, 138.2529),
                        "Germany": (51.1657, 10.4515),
                        "United Kingdom": (55.3781, -3.4360),
                        "France": (46.2276, 2.2137),
                        "Italy": (41.8719, 12.5674),
                        "Canada": (56.1304, -106.3468),
                        "Brazil": (-14.2350, -51.9253),
                        "Australia": (-25.2744, 133.7751),
                        "Spain": (40.4637, -3.7492),
                        "Mexico": (23.6345, -102.5528),
                        "Indonesia": (-0.7893, 113.9213),
                        "Netherlands": (52.1326, 5.2913),
                        "Saudi Arabia": (23.8859, 45.0792),
                        "Turkey": (38.9637, 35.2433),
                        "Switzerland": (46.8182, 8.2275),
                        "Norway": (60.4720, 8.4689),
                        "Sweden": (60.1282, 18.6435),
                        "South Korea": (35.9078, 127.7669),
                        "Ireland": (53.1424, -7.6921),
                        "Taiwan": (23.6978, 120.9605),
                        "Singapore": (1.3521, 103.8198),
                        "Israel": (31.0461, 34.8516),
                        "Belgium": (50.5039, 4.4699),
                        "Austria": (47.5162, 14.5501),
                        "Portugal": (39.3999, -8.2245),
                        "Poland": (51.9194, 19.1451),
                        "Unknown": (0, 0),
                        "Private": (0, 0)
                    }
                    
                    for country, count in top_countries:
                        if country in default_coords and country not in ["Unknown", "Private"]:
                            lat, lon = default_coords[country]
                            country_counts[country] = count
                            country_locations[country] = (lat, lon)
            
            # Draw points for countries with traffic
            if country_counts:
                max_count = max(country_counts.values()) if country_counts else 1
                for country, count in country_counts.items():
                    if country in country_locations:
                        lat, lon = country_locations[country]
                        # Size points based on traffic
                        size = 20 + (count / max_count) * 100
                        # Color points based on traffic intensity
                        color_val = count / max_count
                        color = cm.viridis(color_val)
                        
                        self.map_ax.scatter(lon, lat, s=size, c=[color], alpha=0.7, 
                                          label=f"{country}: {count}")
                        
                        # Add country label for top 5 countries
                        if count > max_count * 0.1:  # Only label significant countries
                            self.map_ax.text(lon, lat, country, fontsize=8, 
                                           ha='center', va='bottom', color='white')
                
                # Draw legend
                self.map_ax.set_xlabel('Longitude', color=self.theme_colors["fg"])
                self.map_ax.set_ylabel('Latitude', color=self.theme_colors["fg"])
                self.map_ax.tick_params(colors=self.theme_colors["fg"])
                
                # Add legend for top countries
                top_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:5]
                legend_text = "\n".join([f"{country}: {count} packets" for country, count in top_countries])
                self.map_ax.text(0.02, 0.02, legend_text, transform=self.map_ax.transAxes, 
                               fontsize=10, color=self.theme_colors["highlight"], 
                               bbox=dict(facecolor=self.theme_colors["highlight"], alpha=0.7))
            else:
                # If we still don't have any country data, show a message
                self.map_ax.text(0.5, 0.5, "Waiting for geolocation data...", 
                               ha='center', va='center', color=self.theme_colors["fg"], fontsize=14)
                
                # Add some placeholder points based on popular Internet routes
                popular_routes = [
                    ("USA-West", "Europe", (37.7749, -122.4194), (48.8566, 2.3522)),  # SF to Paris
                    ("USA-East", "Asia", (40.7128, -74.0060), (35.6762, 139.6503)),  # NYC to Tokyo
                    ("Europe", "Asia", (51.5074, -0.1278), (22.3193, 114.1694)),     # London to Hong Kong
                    ("USA", "South America", (33.7490, -84.3880), (-23.5505, -46.6333)) # Atlanta to Sao Paulo
                ]
                
                for name, dest, (src_lat, src_lon), (dst_lat, dst_lon) in popular_routes:
                    self.map_ax.scatter(src_lon, src_lat, s=20, c=['gray'], alpha=0.3)
                    self.map_ax.scatter(dst_lon, dst_lat, s=20, c=['gray'], alpha=0.3)
                    self.map_ax.plot([src_lon, dst_lon], [src_lat, dst_lat], 'gray', alpha=0.1, linestyle='--')
                
                # Add a note about the placeholder data
                self.map_ax.text(0.5, 0.95, "Sample visualization of common internet routes", 
                               ha='center', va='top', color='gray', fontsize=8,
                               transform=self.map_ax.transAxes)
            
            self.map_fig.tight_layout()
            self.map_canvas.draw()
        
        except Exception as e:
            print(f"Error drawing world map: {e}")
            import traceback
            traceback.print_exc()

    def update_map(self):
        """Update the world map visualization"""
        try:
            # Always try to draw the map even if we don't have valid connections
            # We'll rely on the draw_world_map method to handle the fallback to countries
            
            # Force draw with connection data
            if self.geo_data and 'connections' in self.geo_data:
                # Filter out connections with valid coordinates
                valid_connections = []
                for conn in self.geo_data['connections']:
                    # Skip connections with no geo data or with 0,0 coordinates
                    if ('src_lat' not in conn or 'dst_lat' not in conn or
                        (conn['src_lat'] == 0 and conn['src_lon'] == 0) or 
                        (conn['dst_lat'] == 0 and conn['dst_lon'] == 0)):
                        continue
                    valid_connections.append(conn)
                
                # Only log updates occasionally to reduce console spam
                if not hasattr(self, 'last_map_log_time') or time.time() - self.last_map_log_time > 30:
                    if valid_connections:
                        print(f"Updating map with {len(valid_connections)} valid geo connections")
                    else:
                        print(f"No valid connections for map, using country statistics")
                        if 'countries' in self.geo_data and self.geo_data['countries']:
                            countries = self.geo_data['countries']
                            top_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)[:5]
                            print(f"Top 5 countries: {top_countries}")
                    
                    self.last_map_log_time = time.time()
                
                # Always draw the map even if no valid connections
                # It will fall back to using country statistics
                self.draw_world_map(valid_connections)
                
            # Only print debug info occasionally to reduce console spam
            if not hasattr(self, 'last_debug_log_time') or time.time() - self.last_debug_log_time > 30:
                if self.geo_data and 'connections' in self.geo_data and self.geo_data['connections']:
                    sample_conn = self.geo_data['connections'][0]
                    print(f"Sample connection data: {sample_conn}")
                    self.last_debug_log_time = time.time()
                
        except Exception as e:
            print(f"Error updating map: {e}")
            import traceback
            traceback.print_exc()
    
    def update_connections_table(self, connections, sessions):
        """Update the connections table with fresh data"""
        # Clear table
        for item in self.connections_tree.get_children():
            self.connections_tree.delete(item)
        
        # Sort connections by packet count
        sorted_connections = sorted(connections.items(), key=lambda x: x[1], reverse=True)
        
        # Add top connections
        for conn, count in sorted_connections[:100]:  # Show top 100
            src, dst = conn.split('-')
            
            # Find a session that matches this connection
            app_name = "Unknown"
            website = "Unknown"
            protocol = "Unknown"
            
            for sess_key, sess_data in sessions.items():
                if sess_key.startswith(f"{src}:") and sess_key.find(f"-{dst}:") > 0:
                    protocol = sess_data.get('protocol', 'Unknown')
                    app_name = sess_data.get('app_name', 'Unknown')
                    website = sess_data.get('domain', "Unknown")
                    break
            
            # Get country info if available
            country_info = ""
            if hasattr(self, 'monitor') and self.monitor:
                try:
                    location = self.monitor.get_ip_location(dst)
                    if location['country'] != 'Unknown' and location['country'] != 'Private':
                        country_info = f" ({location['country']})"
                except:
                    pass
            
            # Ensure website is a string before concatenating
            if website is None:
                website = "Unknown"
                
            # Create display string for website column
            website_display = website + country_info
            
            self.connections_tree.insert('', tk.END, values=(
                src, 
                dst, 
                protocol, 
                count, 
                app_name, 
                website_display
            ))
    
    def update_ports_table(self, ports):
        """Update the ports table with fresh data"""
        # Clear table
        for item in self.ports_tree.get_children():
            self.ports_tree.delete(item)
        
        # Sort ports by packet count
        sorted_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)
        
        # Add top ports
        for port, count in sorted_ports[:100]:  # Show top 100
            try:
                service = socket.getservbyport(port)
            except:
                service = "Unknown"
            
            # Find the top application using this port (this would require additional tracking)
            top_app = "Various"
            
            self.ports_tree.insert('', tk.END, values=(port, service, count, top_app))
    
    def update_applications_table(self, applications, domains):
        """Update the applications and domains tables"""
        # Clear application table
        for item in self.apps_tree.get_children():
            self.apps_tree.delete(item)
        
        # Sort applications by bytes
        sorted_apps = sorted(applications.items(), key=lambda x: x[1]['bytes'], reverse=True)
        
        # Add applications
        for app_name, app_data in sorted_apps:
            if app_name != "Unknown":
                bytes_str = f"{app_data['bytes']/1024:.2f} KB"
                conn_count = len(app_data['connections'])
                
                # Ensure domains are valid before joining
                domains_list = list(app_data['domains'])
                # Filter out None values
                domains_list = [d for d in domains_list if d is not None]
                domains_str = ", ".join(domains_list[:5])  # Show up to 5 domains
                
                self.apps_tree.insert('', tk.END, values=(app_name, bytes_str, conn_count, domains_str))
        
        # Clear domains table
        for item in self.domain_tree.get_children():
            self.domain_tree.delete(item)
        
        # Sort domains by hit count
        sorted_domains = sorted(domains.items(), key=lambda x: x[1], reverse=True)
        
        # Build reverse mapping of domains to applications
        domain_to_apps = {}
        for app_name, app_data in applications.items():
            for domain in app_data['domains']:
                if domain is not None:  # Skip None domains
                    if domain not in domain_to_apps:
                        domain_to_apps[domain] = set()
                    domain_to_apps[domain].add(app_name)
        
        # Add domains
        for domain, hits in sorted_domains:
            if domain is not None:  # Skip None domains
                apps_str = ", ".join(list(domain_to_apps.get(domain, ["Unknown"]))[:3])  # Show up to 3 apps
                self.domain_tree.insert('', tk.END, values=(domain, hits, apps_str))
    
    def update_graphs(self, frame):
        """Update the graph plots"""
        try:
            # Clear previous plots
            self.ax1.clear()
            self.ax2.clear()
            self.ax3.clear()
            self.ax4.clear()
            
            # Plot packet rate
            self.ax1.set_facecolor('#3B4252')
            self.ax1.set_title('Packet Rate (pps)', color='#ECEFF4')
            self.ax1.set_xlabel('Time', color='#ECEFF4')
            self.ax1.set_ylabel('Packets/s', color='#ECEFF4')
            self.ax1.tick_params(colors='#ECEFF4')
            self.ax1.grid(True, alpha=0.3)
            if len(self.time_data) > 0 and len(self.packets_data) > 0:
                self.ax1.plot(range(len(self.time_data)), self.packets_data, 'b-')
                # Only show a few time labels to avoid crowding
                if len(self.time_data) > 10:
                    indices = list(range(0, len(self.time_data), len(self.time_data) // 5))
                    self.ax1.set_xticks(indices)
                    self.ax1.set_xticklabels([self.time_data[i] for i in indices])
                else:
                    # Make sure number of ticks matches number of labels
                    indices = list(range(len(self.time_data)))
                    self.ax1.set_xticks(indices)
                    self.ax1.set_xticklabels([self.time_data[i] for i in indices])
            
            # Plot bandwidth
            self.ax2.set_facecolor('#3B4252')
            self.ax2.set_title('Bandwidth Usage (Mbps)', color='#ECEFF4')
            self.ax2.set_xlabel('Time', color='#ECEFF4')
            self.ax2.set_ylabel('Mbps', color='#ECEFF4')
            self.ax2.tick_params(colors='#ECEFF4')
            self.ax2.grid(True, alpha=0.3)
            if len(self.time_data) > 0 and len(self.bytes_data) > 0:
                self.ax2.plot(range(len(self.time_data)), self.bytes_data, 'r-')
                # Only show a few time labels to avoid crowding
                if len(self.time_data) > 10:
                    indices = list(range(0, len(self.time_data), len(self.time_data) // 5))
                    self.ax2.set_xticks(indices)
                    self.ax2.set_xticklabels([self.time_data[i] for i in indices])
                else:
                    # Make sure number of ticks matches number of labels
                    indices = list(range(len(self.time_data)))
                    self.ax2.set_xticks(indices)
                    self.ax2.set_xticklabels([self.time_data[i] for i in indices])
            
            # Plot protocol distribution
            self.ax3.set_facecolor('#3B4252')
            self.ax3.set_title('Protocol Distribution', color='#ECEFF4')
            self.ax3.tick_params(colors='#ECEFF4')
            if self.protocol_data:
                # Convert protocol numbers to names where possible
                protocol_names = {}
                for proto, count in sorted(self.protocol_data.items(), key=lambda x: x[1], reverse=True)[:5]:
                    try:
                        name = socket.getservbyname(str(proto), 'ip')
                    except:
                        try:
                            name = socket.getprotobyname(str(proto))
                        except:
                            name = f"Proto {proto}"
                    protocol_names[name] = count
                
                protocols = list(protocol_names.keys())
                counts = list(protocol_names.values())
                
                # Only create pie chart if we have data
                if counts:
                    colors = plt.cm.tab10(range(len(protocols)))
                    self.ax3.pie(counts, labels=protocols, autopct='%1.1f%%', colors=colors)
            
            # Plot application bandwidth
            self.ax4.set_facecolor('#3B4252')
            self.ax4.set_title('Top Applications Bandwidth', color='#ECEFF4')
            self.ax4.tick_params(colors='#ECEFF4')
            self.ax4.set_xlabel('Application', color='#ECEFF4')
            self.ax4.set_ylabel('KB', color='#ECEFF4')
            
            if hasattr(self.monitor, 'stats') and 'applications' in self.monitor.stats:
                # Get top applications by bandwidth
                top_apps = sorted(self.monitor.stats['applications'].items(), 
                                 key=lambda x: x[1]['bytes'], reverse=True)[:5]
                
                if top_apps:
                    app_names = [app[0] if len(app[0]) <= 15 else app[0][:12]+"..." for app in top_apps]
                    app_bytes = [app[1]['bytes']/1024 for app in top_apps]  # Convert to KB
                    
                    # Only draw bar chart if we have data
                    if len(app_names) > 0 and len(app_bytes) > 0:
                        colors = plt.cm.viridis(range(len(app_names)))
                        bars = self.ax4.bar(range(len(app_names)), app_bytes, color=colors)
                        
                        # Make sure x-ticks match number of bars
                        self.ax4.set_xticks(range(len(app_names)))
                        self.ax4.set_xticklabels(app_names, rotation=45, ha='right')
            
            self.fig.tight_layout(pad=3.0)
            
        except Exception as e:
            print(f"Error updating graphs: {e}")
            import traceback
            traceback.print_exc()
    
    def sort_treeview(self, tree, col, reverse):
        """Sort a treeview by column"""
        data = []
        for item_id in tree.get_children(''):
            values = tree.item(item_id, 'values')
            data.append((values, item_id))
        
        # Determine column type (numeric or string)
        if data:
            try:
                # Try to convert to float for numeric sort
                float(data[0][0][tree['columns'].index(col)])
                data.sort(key=lambda x: float(x[0][tree['columns'].index(col)]), reverse=reverse)
            except (ValueError, TypeError):
                # Otherwise do string sort
                data.sort(key=lambda x: x[0][tree['columns'].index(col)], reverse=reverse)
        
        # Rearrange items in sorted positions
        for idx, item in enumerate(data):
            tree.move(item[1], '', idx)
        
        # Reverse sort next time
        tree.heading(col, command=lambda: self.sort_treeview(tree, col, not reverse))
    
    def on_close(self):
        """Handle window close event"""
        if self.running:
            self.stop_monitoring()
        self.root.destroy()
    
    def export_data(self):
        """Export collected data to a CSV file"""
        try:
            # Create a custom dialog for export options
            export_dialog = tk.Toplevel(self.root)
            export_dialog.title("Export Data")
            export_dialog.geometry("300x200")
            export_dialog.resizable(False, False)
            export_dialog.transient(self.root)
            export_dialog.grab_set()
            
            # Make it look consistent with main app
            export_dialog.configure(bg="#2E3440")
            
            # Add header
            header = tk.Label(export_dialog, text="Select data to export:", 
                             font=("Arial", 12), bg="#2E3440", fg="#ECEFF4")
            header.pack(pady=10)
            
            # Function to handle button click
            def handle_export(data_type):
                export_dialog.destroy()
                
                # Get timestamp for filename
                timestamp = time.strftime("%Y%m%d-%H%M%S")
                
                if data_type == "connections":
                    filename = f"network_connections_{timestamp}.csv"
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Source', 'Destination', 'Protocol', 'Bytes', 'Website', 'Country'])
                        for item_id in self.connections_tree.get_children():
                            values = self.connections_tree.item(item_id)['values']
                            writer.writerow(values)
                    messagebox.showinfo("Export Complete", f"Connections exported to {filename}")
                
                elif data_type == "applications":
                    filename = f"network_applications_{timestamp}.csv"
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Application', 'Connections', 'Traffic (KB)', 'Domains'])
                        for item_id in self.apps_tree.get_children():
                            values = self.apps_tree.item(item_id)['values']
                            writer.writerow(values)
                    messagebox.showinfo("Export Complete", f"Applications exported to {filename}")
                
                elif data_type == "geo":
                    filename = f"network_geolocation_{timestamp}.csv"
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Country', 'Connections', 'Traffic (KB)'])
                        if hasattr(self, 'geo_data') and 'countries' in self.geo_data:
                            for country, count in sorted(self.geo_data['countries'].items(), 
                                                      key=lambda x: x[1], reverse=True):
                                writer.writerow([country, count, self.geo_data.get('country_bytes', {}).get(country, 0) / 1024])
                    messagebox.showinfo("Export Complete", f"Geolocation data exported to {filename}")
            
            # Create buttons for each export option
            btn_connections = tk.Button(export_dialog, text="Export Connections", 
                                      command=lambda: handle_export("connections"),
                                      bg="#4C566A", fg="#ECEFF4", width=20)
            btn_connections.pack(pady=5)
            
            btn_applications = tk.Button(export_dialog, text="Export Applications", 
                                       command=lambda: handle_export("applications"),
                                       bg="#4C566A", fg="#ECEFF4", width=20)
            btn_applications.pack(pady=5)
            
            btn_geo = tk.Button(export_dialog, text="Export Geo Data", 
                              command=lambda: handle_export("geo"),
                              bg="#4C566A", fg="#ECEFF4", width=20)
            btn_geo.pack(pady=5)
            
            btn_cancel = tk.Button(export_dialog, text="Cancel", 
                                 command=export_dialog.destroy,
                                 bg="#BF616A", fg="#ECEFF4", width=20)
            btn_cancel.pack(pady=5)
            
            # Center the dialog on the parent window
            export_dialog.update_idletasks()
            x = self.root.winfo_x() + (self.root.winfo_width() - export_dialog.winfo_width()) // 2
            y = self.root.winfo_y() + (self.root.winfo_height() - export_dialog.winfo_height()) // 2
            export_dialog.geometry(f"+{x}+{y}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting data: {e}")
            print(f"Error exporting data: {e}")
            import traceback
            traceback.print_exc()
    
    def record_traffic(self):
        """Record network traffic to a PCAP file"""
        # This is a placeholder for a feature that would require additional implementation
        messagebox.showinfo("Coming Soon", "Traffic recording feature is coming soon!")
    
    def block_connection(self):
        """Block a network connection"""
        # This is a placeholder for a feature that would require additional implementation
        messagebox.showinfo("Coming Soon", "Connection blocking feature is coming soon!")
    
    def clear_stats(self):
        """Clear all statistics"""
        if self.monitor:
            confirm = messagebox.askokcancel(
                "Clear Statistics", 
                "Are you sure you want to clear all statistics?\nThis cannot be undone."
            )
            if confirm:
                self.monitor.stats = {
                    'total_packets': 0,
                    'total_bytes': 0,
                    'protocols': defaultdict(int),
                    'ports': defaultdict(int),
                    'connections': defaultdict(int),
                    'sessions': defaultdict(dict),
                    'applications': defaultdict(lambda: {'bytes': 0, 'connections': set(), 'domains': set()}),
                    'domains': defaultdict(int),
                    'countries': defaultdict(int),
                    'geo_connections': []
                }
                messagebox.showinfo("Statistics Cleared", "All statistics have been reset.")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
        WinIDS Network Analyzer
        
        A powerful network monitoring and analysis tool for Windows
        
        Features:
        - Real-time network traffic monitoring
        - Application identification
        - Website tracking
        - Geolocation of network connections
        - Data export and visualization
        
        Created as part of the WinIDS Intrusion Detection System
        """
        messagebox.showinfo("About WinIDS Network Analyzer", about_text)

    def apply_theme(self, theme_name):
        """Apply the selected theme to the UI"""
        if theme_name not in self.available_themes:
            return
            
        self.current_theme = theme_name
        self.theme_colors = self.available_themes[theme_name]
        
        # Configure styles
        self.style.configure('TFrame', background=self.theme_colors["bg"])
        self.style.configure('TLabel', background=self.theme_colors["bg"], foreground=self.theme_colors["fg"])
        self.style.configure('TButton', background=self.theme_colors["button"], foreground=self.theme_colors["fg"], padding=6)
        self.style.configure('StartButton.TButton', background='green', foreground='white', padding=10, font=('Arial', 12, 'bold'))
        self.style.configure('StopButton.TButton', background='red', foreground='white', padding=10, font=('Arial', 12, 'bold'))
        self.style.configure('TNotebook', background=self.theme_colors["bg"])
        self.style.configure('TNotebook.Tab', background=self.theme_colors["button"], foreground=self.theme_colors["fg"], padding=(10, 5))
        self.style.map('TNotebook.Tab', background=[('selected', self.theme_colors["accent"])], foreground=[('selected', self.theme_colors["fg"])])
        
        # Treeview colors
        self.style.configure("Treeview", background=self.theme_colors["bg"], foreground=self.theme_colors["fg"], fieldbackground=self.theme_colors["bg"])
        self.style.map('Treeview', background=[('selected', self.theme_colors["accent"])])
        
        # Update root and all frames
        self.root.configure(bg=self.theme_colors["bg"])
        
        # If we have matplotlib figures, update them
        if hasattr(self, 'fig'):
            self.fig.set_facecolor(self.theme_colors["bg"])
            self.ax1.set_facecolor(self.theme_colors["chart_bg"])
            self.ax2.set_facecolor(self.theme_colors["chart_bg"])
            self.ax3.set_facecolor(self.theme_colors["chart_bg"])
            self.ax4.set_facecolor(self.theme_colors["chart_bg"])
            self.canvas.draw()
            
        if hasattr(self, 'map_fig'):
            self.map_fig.set_facecolor(self.theme_colors["bg"])
            self.map_ax.set_facecolor(self.theme_colors["chart_bg"])
            self.map_canvas.draw()

    def start_monitoring(self):
        """Start network monitoring"""
        if not self.running:
            self.monitor = SystemNetworkMonitor()
            if self.monitor.start_capture():
                self.running = True
                
                # Update UI
                self.start_button.configure(state=tk.DISABLED)
                self.stop_button.configure(state=tk.NORMAL)
                self.status_var.set("Status: Monitoring")
                
                # Start update thread
                self.monitor_thread = threading.Thread(target=self.update_data)
                self.monitor_thread.daemon = True
                self.monitor_thread.start()
                
                # Start animation for graphs
                self.traffic_anim = animation.FuncAnimation(
                    self.fig, self.update_graphs, interval=1000, save_count=100)
                self.canvas.draw()
            else:
                messagebox.showerror("Error", "Failed to start network monitoring.\nMake sure you are running as administrator.")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        if self.running:
            # Stop monitor
            if self.monitor:
                self.monitor.stop_capture()
            
            # Update UI
            self.running = False
            self.start_button.configure(state=tk.NORMAL)
            self.stop_button.configure(state=tk.DISABLED)
            self.status_var.set("Status: Stopped")
            
            if hasattr(self, 'traffic_anim'):
                self.traffic_anim.event_source.stop()
    
    def update_data(self):
        """Update data from monitor"""
        last_packet_count = 0
        last_byte_count = 0
        last_time = time.time()
        last_map_update = time.time()
        
        while self.running:
            try:
                # Get current stats
                stats = self.monitor.get_statistics()
                app_stats = self.monitor.get_application_traffic()
                geo_stats = self.monitor.get_geo_data()
                
                # Calculate rates
                current_time = time.time()
                time_delta = current_time - last_time
                
                packet_delta = stats['total_packets'] - last_packet_count
                byte_delta = stats['total_bytes'] - last_byte_count
                
                packet_rate = packet_delta / time_delta if time_delta > 0 else 0
                byte_rate = byte_delta / time_delta if time_delta > 0 else 0
                
                # Update data points
                self.time_data.append(datetime.datetime.now().strftime('%H:%M:%S'))
                self.packets_data.append(packet_rate)
                self.bytes_data.append(byte_rate / 1024 / 1024)  # Convert to Mbps
                
                # Update protocol data
                self.protocol_data = stats['protocols']
                
                # Update geo data
                self.geo_data = geo_stats
                
                # Update queue for main thread
                self.queue.put({
                    'total_packets': stats['total_packets'],
                    'total_bytes': stats['total_bytes'],
                    'packet_rate': packet_rate,
                    'byte_rate': byte_rate,
                    'protocols': stats['protocols'],
                    'connections': stats['connections'],
                    'ports': stats['ports'],
                    'sessions': stats['sessions'],
                    'applications': app_stats['applications'],
                    'domains': app_stats['domains'],
                    'countries': geo_stats['countries'],
                    'geo_connections': geo_stats['connections']
                })
                
                # Update the map occasionally to avoid too much CPU usage
                if current_time - last_map_update > 5:  # Update map every 5 seconds
                    self.root.after(100, self.update_map)
                    last_map_update = current_time
                
                # Update for next iteration
                last_packet_count = stats['total_packets']
                last_byte_count = stats['total_bytes']
                last_time = current_time
                
                # Process queue on main thread
                self.root.after(100, self.process_queue)
                
                time.sleep(1)
                
            except Exception as e:
                print(f"Error updating data: {e}")
                break
    
    def process_queue(self):
        """Process data queue on main thread"""
        try:
            while not self.queue.empty():
                data = self.queue.get(block=False)
                
                # Update statistics labels
                self.total_packets_var.set(f"Total Packets: {data['total_packets']}")
                self.total_traffic_var.set(f"Total Traffic: {data['total_bytes']/1024/1024:.2f} MB")
                self.packet_rate_var.set(f"Packet Rate: {data['packet_rate']:.2f} pps")
                self.bandwidth_var.set(f"Bandwidth: {data['byte_rate']/1024/1024:.2f} Mbps")
                
                # Update connections table
                self.update_connections_table(data['connections'], data['sessions'])
                
                # Update ports table
                self.update_ports_table(data['ports'])
                
                # Update applications table
                self.update_applications_table(data['applications'], data['domains'])
                
                # Store geo data for map updates
                self.geo_data = {
                    'countries': data['countries'],
                    'connections': data['geo_connections']
                }
        except queue.Empty:
            pass
        except Exception as e:
            print(f"Error processing queue: {e}")

def main():
    try:
        # Check if running as admin
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                print("Warning: This application requires administrator privileges for full functionality.")
                print("Some features may not work correctly.")
        except Exception as e:
            print(f"Error checking admin status: {e}")
            
        # Print information about the environment
        print(f"Python version: {sys.version}")
        print(f"Current directory: {os.getcwd()}")
        print(f"Script location: {os.path.abspath(__file__)}")
        
        # Import check for required modules
        required_modules = ["tkinter", "matplotlib", "psutil", "pydivert", "dns"]
        for module in required_modules:
            try:
                __import__(module)
                print(f"Successfully imported {module}")
            except ImportError as e:
                print(f"Error importing {module}: {e}")
        
        # Initialize and run the application
        root = tk.Tk()
        app = NetworkAnalyzerGUI(root)
        
        # Auto-start monitoring after a short delay
        print("Auto-starting network monitoring in 2 seconds...")
        root.after(2000, app.start_monitoring)  # Start monitoring after 2 seconds
        
        root.mainloop()
    except Exception as e:
        print(f"Error in main function: {e}")
        import traceback
        traceback.print_exc()
        
        # Keep the console window open if error occurs
        input("Press Enter to exit...")

if __name__ == "__main__":
    main() 