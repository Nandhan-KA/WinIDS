#!/usr/bin/env python
"""
WinIDS Professional Dashboard

Main graphical user interface for the WinIDS intrusion detection system.
"""

import os
import sys
import time
import logging
import argparse
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
from datetime import datetime

from .fast_run import FastIDS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("WinIDS_dashboard.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("WinIDS-Dashboard")

# Attack colors for visualization
ATTACK_COLORS = {
    'normal': '#95a5a6',  # Gray
    'dos': '#e74c3c',     # Red
    'probe': '#3498db',   # Blue
    'r2l': '#2ecc71',     # Green
    'u2r': '#f39c12'      # Orange
}

class ProDashboard:
    """Professional Dashboard for WinIDS."""
    
    def __init__(self, ids_instance, dark_mode=True):
        """Initialize the dashboard."""
        self.ids = ids_instance
        self.dark_mode = dark_mode
        self.bridge_process = None
        self.running = False
        
        # Create root window
        self.root = tk.Tk()
        self.root.title("WinIDS - Professional Security Dashboard")
        self.root.geometry("1200x700")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Create status variable
        self.status_var = tk.StringVar(value="Initializing...")
        
        # Set theme colors
        self._setup_theme()
        
        # Create widgets
        self._create_widgets()
        
        # Start update task
        self.update_task()
    
    def _setup_theme(self):
        """Set up theme colors."""
        if self.dark_mode:
            self.bg_color = "#2d2d2d"
            self.fg_color = "#f0f0f0"
            self.entry_bg = "#3d3d3d"
            self.button_bg = "#3498db"
            self.button_fg = "#ffffff"
        else:
            self.bg_color = "#f5f5f5"
            self.fg_color = "#333333"
            self.entry_bg = "#ffffff"
            self.button_bg = "#2196f3"
            self.button_fg = "#ffffff"
            
        # Apply colors
        self.root.configure(bg=self.bg_color)
        
        # Create styles
        self.style = ttk.Style()
        self.style.configure("TFrame", background=self.bg_color)
        self.style.configure("TLabel", background=self.bg_color, foreground=self.fg_color)
        self.style.configure("TButton", background=self.button_bg, foreground=self.button_fg)
    
    def _create_widgets(self):
        """Create the dashboard widgets."""
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(main_frame, text="WinIDS Professional Dashboard", font=("Helvetica", 16, "bold"))
        title_label.pack(pady=(0, 10))
        
        # Control panel
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=5)
        
        # Start/Stop buttons
        self.start_button = ttk.Button(control_frame, text="Start Monitoring", command=self.start_ids)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_ids)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Connect to bridge button
        self.connect_button = ttk.Button(control_frame, text="Connect to Bridge", command=self.connect_to_bridge)
        self.connect_button.pack(side=tk.RIGHT, padx=5)
        
        # Status display
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=5)
        
        # Status indicators
        ttk.Label(status_frame, text="Status:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.status_label = ttk.Label(status_frame, text="Stopped")
        self.status_label.grid(row=0, column=1, sticky="w", padx=5, pady=2)
        
        ttk.Label(status_frame, text="Bridge:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.bridge_label = ttk.Label(status_frame, text="Disconnected")
        self.bridge_label.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        
        ttk.Label(status_frame, text="Uptime:").grid(row=0, column=2, sticky="w", padx=5, pady=2)
        self.uptime_label = ttk.Label(status_frame, text="0s")
        self.uptime_label.grid(row=0, column=3, sticky="w", padx=5, pady=2)
        
        ttk.Label(status_frame, text="Packets:").grid(row=1, column=2, sticky="w", padx=5, pady=2)
        self.packets_label = ttk.Label(status_frame, text="0")
        self.packets_label.grid(row=1, column=3, sticky="w", padx=5, pady=2)
        
        ttk.Label(status_frame, text="Alerts:").grid(row=0, column=4, sticky="w", padx=5, pady=2)
        self.alerts_label = ttk.Label(status_frame, text="0")
        self.alerts_label.grid(row=0, column=5, sticky="w", padx=5, pady=2)
        
        # Attack log
        log_frame = ttk.Frame(main_frame)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        ttk.Label(log_frame, text="Attack Log:").pack(anchor="w")
        
        self.alert_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD)
        self.alert_text.pack(fill=tk.BOTH, expand=True)
        self.alert_text.config(bg=self.entry_bg, fg=self.fg_color)
        
        # Configure text tags for different attack types
        for attack_type, color in ATTACK_COLORS.items():
            self.alert_text.tag_configure(attack_type, foreground=color, font=("Helvetica", 10, "bold"))
        
        # Status bar
        status_bar = ttk.Frame(self.root)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        status_label = ttk.Label(status_bar, textvariable=self.status_var, padding=(5, 2))
        status_label.pack(side=tk.LEFT)
    
    def connect_to_bridge(self):
        """Connect to IDS Bridge."""
        # Try to connect to bridge
        if self.ids.connect_to_bridge():
            self.status_var.set("Connected to IDS Bridge: Receiving real-time attack data")
            self.bridge_label.config(text="Connected")
            self.connect_button.config(state=tk.DISABLED)
        else:
            self.status_var.set("Failed to connect to IDS Bridge")
            self.bridge_label.config(text="Disconnected")
    
    def start_ids(self):
        """Start IDS monitoring."""
        try:
            self.ids.start()
            self.running = True
            logger.info("Started IDS monitoring")
            self.status_var.set("IDS monitoring started - Analyzing network traffic")
            self.status_label.config(text="Running")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
        except Exception as e:
            logger.error(f"Error starting IDS: {e}")
            self.status_var.set(f"Error starting IDS: {str(e)}")
            
    def stop_ids(self):
        """Stop IDS monitoring."""
        try:
            self.ids.stop()
            self.running = False
            logger.info("Stopped IDS monitoring")
            self.status_var.set("IDS monitoring stopped")
            self.status_label.config(text="Stopped")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
        except Exception as e:
            logger.error(f"Error stopping IDS: {e}")
            self.status_var.set(f"Error stopping IDS: {str(e)}")
    
    def update_task(self):
        """Update dashboard periodically."""
        # Get current stats
        if hasattr(self.ids, 'get_stats'):
            stats = self.ids.get_stats()
            
            # Update stat labels
            self.uptime_label.config(text=f"{int(stats['uptime'])}s")
            self.packets_label.config(text=f"{stats['total_packets']}")
            self.alerts_label.config(text=f"{stats['alerts']}")
            
            # Update bridge connection status
            if stats.get('bridge_connected', False):
                self.bridge_label.config(text="Connected")
                self.connect_button.config(state=tk.DISABLED)
            else:
                self.bridge_label.config(text="Disconnected")
                self.connect_button.config(state=tk.NORMAL)
        
        # Process alerts from queue if available
        if hasattr(self.ids, 'alert_queue') and not self.ids.alert_queue.empty():
            while not self.ids.alert_queue.empty():
                try:
                    alert = self.ids.alert_queue.get()
                    
                    # Get alert type for coloring
                    attack_type = alert.get('attack_type', 'unknown').lower()
                    confidence = alert.get('confidence', 0)
                    
                    # Format alert text
                    timestamp = alert.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                    alert_text = f"[{timestamp}] - [{attack_type.upper()}] attack detected - Confidence: {confidence:.2f}"
                    
                    # Add to text widget with tag for color
                    if attack_type in ATTACK_COLORS:
                        self.alert_text.insert(tk.END, alert_text + '\n', attack_type)
                    else:
                        self.alert_text.insert(tk.END, alert_text + '\n')
                    self.alert_text.see(tk.END)
                except Exception as e:
                    logger.error(f"Error processing alert: {e}")
        
        # Schedule the next update
        self.root.after(1000, self.update_task)
    
    def on_close(self):
        """Handle window close event."""
        if self.running:
            self.stop_ids()
            
        # Kill bridge process if we started it
        if self.bridge_process:
            try:
                self.bridge_process.terminate()
                logger.info("Terminated IDS Bridge process")
            except:
                pass
                
        self.root.destroy()
        
    def run(self):
        """Run the dashboard."""
        # Auto-connect to bridge if available
        self.root.after(1000, self.connect_to_bridge)
        
        # Start the main loop
        self.root.mainloop()

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="WinIDS Professional Dashboard")
    
    parser.add_argument("--model", type=str, default="models/best_fast_model.h5",
                      help="Path to trained IDS model")
    parser.add_argument("--norm-params", type=str, default="models/normalization_params.json",
                      help="Path to normalization parameters")
    parser.add_argument("--threshold", type=float, default=0.7,
                      help="Detection threshold (0.5-0.99)")
    parser.add_argument("--bridge-host", type=str, default="localhost",
                      help="IDS Bridge host")
    parser.add_argument("--bridge-port", type=int, default=5000,
                      help="IDS Bridge port")
    parser.add_argument("--light-mode", action="store_true",
                      help="Use light mode theme (default is dark mode)")
    parser.add_argument("--disable-attacks", action="store_true",
                      help="Completely disable all attack functionality")
    
    return parser.parse_args()

def main():
    """Main entry point."""
    # Parse command line arguments
    args = parse_args()
    
    # Create FastIDS instance
    ids = FastIDS(
        model_path=args.model,
        norm_params_path=args.norm_params,
        threshold=args.threshold,
        bridge_host=args.bridge_host,
        bridge_port=args.bridge_port
    )
    
    # Store the disable_attacks flag in the ids instance
    ids.disable_attacks = args.disable_attacks
    
    # Create and run dashboard
    dashboard = ProDashboard(ids, dark_mode=not args.light_mode)
    dashboard.run()
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 