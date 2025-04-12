import os
import sys
import threading
import time
import socket
import logging
import ipaddress
import subprocess
import geoip2.database
import geoip2.errors
import pydivert
import psutil
import dns.resolver
from collections import defaultdict, deque
import traceback
import scapy.all as scapy
from scapy.layers import http
import pandas as pd
import numpy as np
from datetime import datetime
import queue
import json
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTP
import struct
import dns.reversename
from pathlib import Path
import ctypes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('system_traffic.log')
    ]
)
logger = logging.getLogger(__name__)

# Import GeoIP database downloader
try:
    from .download_geoip_db import download_geolite2_db
except ImportError:
    # Define a minimal version if the module is not available
    def download_geolite2_db():
        print("GeoIP database downloader not available. Using default paths.")
        return "geoip_db/GeoLite2-City.mmdb", "geoip_db/GeoLite2-Country.mmdb"

class SystemNetworkMonitor:
    """
    A system-wide network traffic monitor using WinDivert to capture packets
    across the entire Windows system.
    """
    
    def __init__(self, interface="0", port=0):
        self.interface = interface
        self.port = port
        # Check admin privileges
        try:
            self.is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            self.is_admin = False
        self.stop_flag = threading.Event()
        self.packet_queue = queue.Queue()
        self.session_tracker = defaultdict(dict)
        self.traffic_stats = defaultdict(int)
        self.dns_cache = {}  # Cache for DNS lookups
        self.app_traffic = defaultdict(lambda: {'sent_bytes': 0, 'recv_bytes': 0, 'connections': set()})
        self.geo_cache = {}  # Cache for GeoIP lookups
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler('system_traffic.log'),
                logging.StreamHandler()
            ]
        )
        
        # Initialize statistics
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': defaultdict(int),
            'ports': defaultdict(int),
            'connections': defaultdict(int),
            'sessions': defaultdict(dict),
            'applications': defaultdict(lambda: {'bytes': 0, 'connections': set(), 'domains': set()}),
            'domains': defaultdict(int),
            'countries': defaultdict(int),  # Track packets by country
            'geo_connections': []  # Store geolocation data for connections
        }
        
        # Initialize GeoIP database
        self._init_geoip()
        
        # Initialize DNS cache
        self.dns_cache = {}
        self.domain_queue = deque(maxlen=100)
        self.dns_thread = None
        
        # Initialize process cache
        self.process_cache = {}
        
        # Initialize analysis thread
        self.analysis_thread = None
    
    def _init_geoip(self):
        """Initialize GeoIP database for IP location lookup"""
        self.geoip_city = None
        self.geoip_country = None
        
        try:
            # Download GeoIP database if needed
            city_db_path, country_db_path = download_geolite2_db()
            
            # Verify database files exist
            if not os.path.exists(city_db_path) or not os.path.exists(country_db_path):
                logging.warning("GeoIP database files not found at expected paths")
                logging.info("Using fallback for GeoIP lookups - location data will be limited")
                return
            
            # Open GeoIP readers
            self.geoip_city = geoip2.database.Reader(city_db_path)
            self.geoip_country = geoip2.database.Reader(country_db_path)
            logging.info(f"Initialized GeoIP database from {city_db_path}")

        except Exception as e:
            print("Exception occured: ",e)
    def get_ip_location(self, ip):
        """Get location information for an IP address"""
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        
        # Skip private IP addresses
        try:
            # Try to handle various types of IP address formats
            if ip in ['0.0.0.0', '::', 'Unknown']:
                # Special case for default/unknown IP addresses
                fallback_location = {
                    'country': 'Unknown',
                    'country_code': 'XX',
                    'city': 'Unknown',
                    'latitude': 0,
                    'longitude': 0
                }
                self.geo_cache[ip] = fallback_location
                return fallback_location
                
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                location = {
                    'country': 'Private',
                    'country_code': 'XX',
                    'city': 'Private Network',
                    'latitude': 37.751,  # Use central US coordinates for private IPs
                    'longitude': -97.822  # This makes them show up on the map
                }
                self.geo_cache[ip] = location
                return location
        except Exception as e:
            # If IP parsing fails, return unknown but with coordinates
            location = {
                'country': 'Unknown',
                'country_code': 'XX',
                'city': 'Unknown',
                'latitude': 0,
                'longitude': 0
            }
            self.geo_cache[ip] = location
            return location
        
        # Lookup location
        try:
            if self.geoip_city:
                try:
                    response = self.geoip_city.city(ip)
                    
                    # Get country name with fallback
                    country_name = 'Unknown'
                    country_code = 'XX'
                    if hasattr(response, 'country') and response.country:
                        country_name = response.country.name or 'Unknown'
                        country_code = response.country.iso_code or 'XX'
                    
                    # Get city name with fallback
                    city_name = 'Unknown'
                    if hasattr(response, 'city') and response.city:
                        city_name = response.city.name or 'Unknown'
                    
                    # Get coordinates with fallback
                    latitude = 0
                    longitude = 0
                    if hasattr(response, 'location') and response.location:
                        latitude = response.location.latitude or 0
                        longitude = response.location.longitude or 0
                    
                    # Construct location data
                    location = {
                        'country': country_name,
                        'country_code': country_code,
                        'city': city_name,
                        'latitude': latitude,
                        'longitude': longitude
                    }
                    self.geo_cache[ip] = location
                    return location
                except Exception as e:
                    logging.debug(f"Specific GeoIP lookup error for {ip}: {str(e)}")
                    
                    # Try to get country information only from country database as fallback
                    try:
                        if self.geoip_country:
                            country_resp = self.geoip_country.country(ip)
                            location = {
                                'country': country_resp.country.name or 'Unknown',
                                'country_code': country_resp.country.iso_code or 'XX',
                                'city': 'Unknown',
                                'latitude': 0, 
                                'longitude': 0
                            }
                            
                            # Use country centroid if we have the country but no coordinates
                            country_centroids = {
                                'US': (37.0902, -95.7129),  # United States
                                'CN': (35.8617, 104.1954),  # China
                                'RU': (61.5240, 105.3188),  # Russia
                                'GB': (55.3781, -3.4360),   # United Kingdom
                                'DE': (51.1657, 10.4515),   # Germany
                                'FR': (46.2276, 2.2137),    # France
                                'JP': (36.2048, 138.2529),  # Japan
                                'IN': (20.5937, 78.9629),   # India
                                'CA': (56.1304, -106.3468), # Canada
                                'AU': (-25.2744, 133.7751), # Australia
                                'BR': (-14.2350, -51.9253), # Brazil
                            }
                            
                            if location['country_code'] in country_centroids:
                                location['latitude'] = country_centroids[location['country_code']][0]
                                location['longitude'] = country_centroids[location['country_code']][1]
                            
                            self.geo_cache[ip] = location
                            return location
                    except Exception:
                        pass
            
            # If we reach here, GeoIP databases failed to provide useful information
            # Return placeholder with some coordinates to show on map
            location = {
                'country': 'Unknown',
                'country_code': 'XX',
                'city': 'Unknown',
                'latitude': 37.751,  # Use central US coordinates as fallback
                'longitude': -97.822
            }
            self.geo_cache[ip] = location
            return location
            
        except Exception as e:
            # If lookup fails, return unknown with coordinates
            logging.debug(f"GeoIP lookup failed for {ip}: {e}")
            location = {
                'country': 'Unknown',
                'country_code': 'XX',
                'city': 'Unknown',
                'latitude': 37.751,  # Use central US coordinates as fallback
                'longitude': -97.822
            }
            self.geo_cache[ip] = location
            return location
    
    def start_capture(self):
        """Start system-wide traffic capture"""
        try:
            # Start packet capture thread
            self.capture_thread = threading.Thread(target=self._capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
            # Start analysis thread
            self.analysis_thread = threading.Thread(target=self._analyze_packets)
            self.analysis_thread.daemon = True
            self.analysis_thread.start()

            # Start statistics thread
            self.stats_thread = threading.Thread(target=self._print_stats)
            self.stats_thread.daemon = True
            self.stats_thread.start()

            # Start DNS resolution thread
            self.dns_thread = threading.Thread(target=self._resolve_domains)
            self.dns_thread.daemon = True 
            self.dns_thread.start()

            logging.info("Started system-wide network monitoring")
            return True

        except Exception as e:
            logging.error(f"Failed to start capture: {e}")
            return False
    
    def _capture_packets(self):
        """Capture all network packets using WinDivert"""
        try:
            # Create WinDivert handle for all network traffic
            with pydivert.WinDivert("true") as w:
                logging.info("Started packet capture")
                while not self.stop_flag.is_set():
                    try:
                        # Read a packet
                        packet = w.recv()
                        # Forward the packet to maintain internet connectivity
                        w.send(packet)
                        # Add to queue for analysis
                        self.packet_queue.put(packet)
                    except Exception as e:
                        if not self.stop_flag.is_set():
                            logging.error(f"Error capturing packet: {e}")
        except Exception as e:
            logging.error(f"Capture error: {e}")
    
    def _analyze_packets(self):
        """Analyze captured packets"""
        while not self.stop_flag.is_set():
            try:
                # Get packet from queue
                packet = self.packet_queue.get(timeout=1)
                
                # Convert WinDivert packet to scapy packet for analysis
                # Fix for memoryview issue - convert memoryview to bytes before processing
                raw_data = bytes(packet.raw)
                
                try:
                    scapy_packet = IP(raw_data)
                    
                    # Get process information
                    process_info = self._get_process_for_packet(scapy_packet, scapy_packet.src, scapy_packet[TCP].sport, scapy_packet.dst, scapy_packet[TCP].dport)
                    
                    # Analyze the packet details
                    self._analyze_packet_details(scapy_packet, packet, raw_data, process_info)
                    
                except Exception as e:
                    logging.debug(f"Error analyzing packet: {e}")
                    continue
                    
            except queue.Empty:
                continue
            except Exception as e:
                if not self.stop_flag.is_set():
                    logging.error(f"Error in packet analysis: {e}")
                    continue
    
    def _get_process_for_packet(self, scapy_packet, local_ip, local_port, remote_ip, remote_port):
        """Get the process responsible for a packet"""
        try:
            # Create a unique key for this connection
            key = f"{local_ip}:{local_port}-{remote_ip}:{remote_port}"
            
            # If we have a recent entry in the cache, return it
            if key in self.session_tracker:
                process_info = self.session_tracker[key]
                if process_info.get('name', 'Unknown') != 'Unknown' and time.time() - process_info.get('last_updated', 0) < 60:
                    return process_info
            
            # Initialize the session tracker entry if it doesn't exist
            if key not in self.session_tracker:
                self.session_tracker[key] = {'pid': 0, 'name': 'Unknown', 'path': '', 'create_time': 0, 'last_updated': time.time()}
            
            # Enhanced process detection - try multiple approaches
            found_process = False
            
            # First try - use psutil.net_connections() with extended kinds
            try:
                # Try TCP and UDP connections together - this increases chances of getting processes
                for kind in ['tcp', 'udp', 'all']:
                    if found_process:
                        break
                        
                    try:
                        connections = psutil.net_connections(kind=kind)
                        
                        # First try exact match for local and remote
                        for conn in connections:
                            try:
                                if not hasattr(conn, 'pid') or not conn.pid:
                                    continue
                                    
                                if (hasattr(conn, 'laddr') and conn.laddr and 
                                    hasattr(conn, 'raddr') and conn.raddr and
                                    conn.laddr.ip == local_ip and conn.laddr.port == local_port and
                                    conn.raddr.ip == remote_ip and conn.raddr.port == remote_port):
                                    
                                    # Exact match found
                                    proc = psutil.Process(conn.pid)
                                    process_info = {
                                        'pid': conn.pid,
                                        'name': proc.name(),
                                        'path': proc.exe() if hasattr(proc, 'exe') else '',
                                        'create_time': proc.create_time() if hasattr(proc, 'create_time') else 0,
                                        'last_updated': time.time(),
                                        'match_type': 'exact'
                                    }
                                    self.session_tracker[key] = process_info
                                    found_process = True
                                    return process_info
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                continue
                        
                        # Then try port-only match if exact match failed
                        if not found_process:
                            for conn in connections:
                                try:
                                    if not hasattr(conn, 'pid') or not conn.pid:
                                        continue
                                        
                                    if (hasattr(conn, 'laddr') and conn.laddr and 
                                        conn.laddr.port == local_port):
                                        
                                        # Port match found
                                        proc = psutil.Process(conn.pid)
                                        process_info = {
                                            'pid': conn.pid,
                                            'name': proc.name(),
                                            'path': proc.exe() if hasattr(proc, 'exe') else '',
                                            'create_time': proc.create_time() if hasattr(proc, 'create_time') else 0,
                                            'last_updated': time.time(),
                                            'match_type': 'port'
                                        }
                                        self.session_tracker[key] = process_info
                                        found_process = True
                                        return process_info
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    continue
                                    
                    except Exception as e:
                        logging.debug(f"Error getting {kind} connections: {e}")
            except Exception as e:
                logging.debug(f"Error in first process detection approach: {e}")
            
            # Second try - use direct process iteration with connection check
            if not found_process:
                try:
                    # Go through each process and check if it has our connection
                    for proc in psutil.process_iter(['pid', 'name', 'exe']):
                        try:
                            # Skip system processes with common errors
                            if proc.pid < 10:
                                continue
                                
                            proc_connections = []
                            try:
                                proc_connections = proc.connections(kind='all')
                            except (psutil.AccessDenied, psutil.NoSuchProcess):
                                continue
                                
                            # Check each connection for matches
                            for conn in proc_connections:
                                try:
                                    # Port match (more lenient)
                                    if (hasattr(conn, 'laddr') and conn.laddr and 
                                        conn.laddr.port == local_port):
                                        
                                        # Found match
                                        process_info = {
                                            'pid': proc.info['pid'],
                                            'name': proc.info['name'],
                                            'path': proc.info['exe'] if 'exe' in proc.info else '',
                                            'create_time': proc.create_time() if hasattr(proc, 'create_time') else 0,
                                            'last_updated': time.time(),
                                            'match_type': 'process_iter'
                                        }
                                        self.session_tracker[key] = process_info
                                        found_process = True
                                        return process_info
                                except Exception:
                                    continue
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                except Exception as e:
                    logging.debug(f"Error in second process detection approach: {e}")
            
            # Third try - check our existing process database for similar connections
            if not found_process:
                try:
                    # Look for connections with matching local port in our tracker
                    for existing_key, existing_info in self.session_tracker.items():
                        if (existing_info.get('name', 'Unknown') != 'Unknown' and
                            existing_key.startswith(f"{local_ip}:{local_port}-")):
                            
                            # Copy the process info but mark as inferred
                            process_info = existing_info.copy()
                            process_info['match_type'] = 'inferred'
                            process_info['last_updated'] = time.time()
                            self.session_tracker[key] = process_info
                            found_process = True
                            return process_info
                except Exception as e:
                    logging.debug(f"Error in third process detection approach: {e}")
            
            # If local IP is localhost or port is a well-known service port, try to infer
            if not found_process:
                # Identify common services
                if local_ip == '127.0.0.1' or local_ip == '::1':
                    if local_port == 80 or local_port == 8080:
                        self.session_tracker[key] = {
                            'pid': 0, 'name': 'Web Server', 'path': '', 
                            'last_updated': time.time(), 'match_type': 'well_known'
                        }
                        return self.session_tracker[key]
                    elif local_port == 443 or local_port == 8443:
                        self.session_tracker[key] = {
                            'pid': 0, 'name': 'Web Server (HTTPS)', 'path': '', 
                            'last_updated': time.time(), 'match_type': 'well_known'
                        }
                        return self.session_tracker[key]
            
            # If everything failed, try to match common applications by port
            common_apps = {
                # Web ports
                80: 'Web Browser', 443: 'Web Browser', 8080: 'Web Browser',
                # Email ports
                25: 'Email Client', 110: 'Email Client', 143: 'Email Client',
                465: 'Email Client', 587: 'Email Client', 993: 'Email Client',
                # DNS
                53: 'DNS Client',
                # Common application ports
                3389: 'Remote Desktop', 22: 'SSH Client',
                5353: 'mDNS/Bonjour',
                1900: 'SSDP/UPnP'
            }
            
            if remote_port in common_apps and not found_process:
                self.session_tracker[key] = {
                    'pid': 0, 'name': common_apps[remote_port], 
                    'path': '', 'last_updated': time.time(),
                    'match_type': 'common_port'
                }
                return self.session_tracker[key]
            
            # Last resort - check running processes for common names
            if not found_process:
                try:
                    browser_processes = ['chrome.exe', 'msedge.exe', 'firefox.exe', 'iexplore.exe', 'brave.exe', 'safari.exe']
                    if remote_port == 443 or remote_port == 80 or remote_port == 8080:
                        for proc in psutil.process_iter(['pid', 'name']):
                            try:
                                if proc.info['name'].lower() in browser_processes:
                                    process_info = {
                                        'pid': proc.info['pid'],
                                        'name': proc.info['name'],
                                        'last_updated': time.time(),
                                        'match_type': 'common_process'
                                    }
                                    self.session_tracker[key] = process_info
                                    found_process = True
                                    return process_info
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                continue
                except Exception as e:
                    logging.debug(f"Error in common process check: {e}")
                
            # If all else fails, return Unknown
            self.session_tracker[key]['last_updated'] = time.time()
            return self.session_tracker[key]
                
        except Exception as e:
            logging.debug(f"Error getting process: {e}")
            return {'pid': 0, 'name': 'Unknown', 'path': '', 'create_time': 0, 'last_updated': time.time()}
    
    def _update_process_list(self):
        """Update the list of all running processes with network activity"""
        try:
            # Update every 5 seconds at most to avoid performance issues
            current_time = time.time()
            if hasattr(self, '_last_process_update') and current_time - self._last_process_update < 5:
                return
            
            self._last_process_update = current_time
            
            # Track already added processes to avoid duplicates
            added_processes = set()
            
            # First, get all network connections with associated processes
            try:
                # Get all connections (TCP and UDP)
                all_connections = []
                all_connections.extend(psutil.net_connections(kind='tcp'))
                all_connections.extend(psutil.net_connections(kind='udp'))
                
                for conn in all_connections:
                    if conn.pid and conn.pid > 0:
                        try:
                            proc = psutil.Process(conn.pid)
                            proc_name = proc.name()
                            
                            # Skip already processed PIDs
                            if proc.pid in added_processes:
                                continue
                                
                            added_processes.add(proc.pid)
                            
                            # Add to application stats if not already there
                            if proc_name not in self.stats['applications']:
                                self.stats['applications'][proc_name] = {
                                    'bytes': 0,
                                    'connections': set(),
                                    'domains': set(),
                                    'pid': proc.pid
                                }
                            
                            # Create connection key
                            if hasattr(conn, 'laddr') and conn.laddr and hasattr(conn, 'raddr') and conn.raddr:
                                conn_key = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}-{conn.type}"
                                self.stats['applications'][proc_name]['connections'].add(conn_key)
                                
                                # Add process to session tracker for future packets
                                self.session_tracker[conn_key] = {
                                    'pid': proc.pid,
                                    'name': proc_name,
                                    'path': proc.exe() if hasattr(proc, 'exe') else '',
                                    'create_time': proc.create_time() if hasattr(proc, 'create_time') else 0
                                }
                        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                            continue
                        except Exception as e:
                            logging.debug(f"Error processing connection for process {conn.pid}: {e}")
            except Exception as e:
                logging.debug(f"Error getting network connections: {e}")
            
            # Now scan all running processes to ensure we catch everything
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
                    try:
                        # Skip already processed PIDs
                        if proc.info['pid'] in added_processes:
                            continue
                            
                        added_processes.add(proc.info['pid'])
                        
                        # Add to application stats if not already there
                        app_name = proc.info['name']
                        if app_name not in self.stats['applications']:
                            self.stats['applications'][app_name] = {
                                'bytes': 0,
                                'connections': set(),
                                'domains': set(),
                                'pid': proc.info['pid']
                            }
                    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                        continue
                    except Exception as e:
                        logging.debug(f"Error processing process {proc.info.get('name')}: {e}")
            except Exception as e:
                logging.debug(f"Error listing processes: {e}")
            
            # Log the number of applications found
            logging.debug(f"Found {len(self.stats['applications'])} applications with network activity")
            
        except Exception as e:
            logging.debug(f"Error updating process list: {e}")
    
    def _analyze_packet_details(self, scapy_packet, original_packet, raw_data, process_info):
        """Analyze packet details and update statistics"""
        try:
            # Update the process list periodically
            self._update_process_list()
            
            # Get IP addresses
            ip_src = scapy_packet.src
            ip_dst = scapy_packet.dst
            
            # Skip localhost traffic
            if ip_src == '127.0.0.1' and ip_dst == '127.0.0.1':
                return
            
            # Update basic statistics
            packet_len = len(raw_data)
            self.stats['total_packets'] += 1
            self.stats['total_bytes'] += packet_len
            
            # Check protocol
            proto = 'Other'
            src_port = 0
            dst_port = 0
            domain = None
            
            # Parse TCP packet
            if scapy_packet.haslayer(TCP):
                proto = 'TCP'
                src_port = scapy_packet[TCP].sport
                dst_port = scapy_packet[TCP].dport
                
                # Check if this is HTTP/HTTPS
                if src_port == 80 or dst_port == 80:
                    proto = 'HTTP'
                elif src_port == 443 or dst_port == 443:
                    proto = 'HTTPS'
                
                # Try to parse HTTP
                if proto == 'HTTP' and scapy_packet.haslayer(http.HTTP):
                    # This is an HTTP packet with payload
                    if hasattr(scapy_packet[http.HTTP], 'Host'):
                        domain = scapy_packet[http.HTTP].Host.decode()
                        self.stats['domains'][domain] += 1
                        
                        # Associate domain with application
                        if process_info and process_info.get('name') != 'Unknown':
                            app_name = process_info.get('name')
                            if app_name in self.stats['applications']:
                                self.stats['applications'][app_name]['domains'].add(domain)
                
            # Parse UDP packet
            elif scapy_packet.haslayer(UDP):
                proto = 'UDP'
                src_port = scapy_packet[UDP].sport
                dst_port = scapy_packet[UDP].dport
                
                # Check if this is DNS
                if src_port == 53 or dst_port == 53:
                    proto = 'DNS'
                    # Try to extract domain from DNS query
                    try:
                        if scapy_packet.haslayer(scapy.DNS) and scapy_packet[scapy.DNS].qr == 0:  # It's a query
                            if scapy_packet[scapy.DNS].qd:
                                query_domain = scapy_packet[scapy.DNS].qd.qname.decode()
                                if query_domain:
                                    domain = query_domain.rstrip('.')
                                    self.stats['domains'][domain] += 1
                                    
                                    # Associate domain with application
                                    if process_info and process_info.get('name') != 'Unknown':
                                        app_name = process_info.get('name')
                                        if app_name in self.stats['applications']:
                                            self.stats['applications'][app_name]['domains'].add(domain)
                    except:
                        pass
            
            # Update protocol counter
            self.stats['protocols'][proto] += 1
            
            # Update port statistics (skip port 0)
            if src_port > 0:
                self.stats['ports'][src_port] += 1
            if dst_port > 0:
                self.stats['ports'][dst_port] += 1
            
            # Update session information
            session_key = f"{ip_src}:{src_port}-{ip_dst}:{dst_port}-{proto}"
            if session_key not in self.stats['sessions']:
                self.stats['sessions'][session_key] = {
                    'src_ip': ip_src,
                    'dst_ip': ip_dst,
                        'src_port': src_port,
                        'dst_port': dst_port,
                    'protocol': proto,
                    'bytes': 0,
                    'packets': 0,
                    'start_time': time.time(),
                    'last_time': time.time(),
                    'process': process_info.get('name', 'Unknown'),
                    'pid': process_info.get('pid', 0)
                }
                
                # Add domain if available
                if domain:
                    self.stats['sessions'][session_key]['domain'] = domain
            
            # Update session counters
            self.stats['sessions'][session_key]['bytes'] += packet_len
            self.stats['sessions'][session_key]['packets'] += 1
            self.stats['sessions'][session_key]['last_time'] = time.time()
            
            # Update application information
            app_name = process_info.get('name', 'Unknown')
            if app_name != 'Unknown':
                # Get or create application entry
                if app_name not in self.stats['applications']:
                    self.stats['applications'][app_name] = {
                        'bytes': 0,
                        'connections': set(),
                        'domains': set(),
                        'pid': process_info.get('pid', 0)
                    }
                
                # Update application traffic
                self.stats['applications'][app_name]['bytes'] += packet_len
                self.stats['applications'][app_name]['connections'].add(session_key)
                
                # Add domain if available
                if domain:
                    self.stats['applications'][app_name]['domains'].add(domain)
                    
            # Add connection to geolocation data if it's not a private IP
            try:
                if not ipaddress.ip_address(ip_dst).is_private:
                    # Get destination location
                    dst_location = self.get_ip_location(ip_dst)
                    self.stats['countries'][dst_location['country']] += 1
                    
                    # Add unique connection to geo_connections list if it's not already there
                    connection = {
                        'src_ip': ip_src,
                        'dst_ip': ip_dst,
                        'dst_country': dst_location['country'],
                        'dst_city': dst_location['city'],
                        'latitude': dst_location['latitude'],
                        'longitude': dst_location['longitude'],
                        'protocol': proto,
                        'port': dst_port,
                        'process': process_info.get('name', 'Unknown'),
                        'bytes': packet_len
                    }
                    
                    # Check if this connection already exists
                    exists = False
                    for conn in self.stats['geo_connections']:
                        if (conn['src_ip'] == ip_src and conn['dst_ip'] == ip_dst and
                            conn['protocol'] == proto and conn['port'] == dst_port):
                            # Update existing connection
                            conn['bytes'] += packet_len
                            exists = True
                            break
                    
                    # Add new connection
                    if not exists:
                        self.stats['geo_connections'].append(connection)
                        # Keep list manageable size
                        if len(self.stats['geo_connections']) > 100:
                            self.stats['geo_connections'].pop(0)
            except Exception as e:
                logging.debug(f"Error updating geolocation data: {e}")
        
        except Exception as e:
            logging.debug(f"Error analyzing packet details: {e}")
            import traceback
            traceback.print_exc()
    
    def _resolve_domains(self):
        """Resolve domain names for IP addresses with enhanced persistence"""
        while not self.stop_flag.is_set():
            try:
                # Sleep to avoid excessive CPU usage
                time.sleep(2)  # Reduced wait time for more frequent checks
                
                # Process more sessions per cycle for better coverage
                count = 0
                max_resolves = 20  # Increased from 10 to 20
                
                # Create a copy of the sessions to avoid modification during iteration
                sessions_to_process = list(self.stats['sessions'].items())
                
                # First, prioritize sessions without domain info
                for session_key, session in sessions_to_process:
                    # Limit updates per cycle
                    if count >= max_resolves:
                        break
                    
                    # Only resolve non-private IPs without domain info
                    try:
                        dst_ip = session['dst_ip']
                        if (not ipaddress.ip_address(dst_ip).is_private and
                            ('domain' not in session or session['domain'] == 'Unknown')):
                            
                            # Check cache first
                            if dst_ip in self.dns_cache and self.dns_cache[dst_ip] != 'Unknown':
                                session['domain'] = self.dns_cache[dst_ip]
                            else:
                                # Try to resolve domain with better error handling
                                try:
                                    # Try reverse DNS lookup
                                    addr = dns.reversename.from_address(dst_ip)
                                    answers = dns.resolver.resolve(addr, "PTR")
                                    if answers:
                                        domain = str(answers[0]).rstrip('.')
                                        # Filter out non-meaningful responses
                                        if not domain.endswith('.in-addr.arpa') and not domain.endswith('.ip6.arpa'):
                                            self.dns_cache[dst_ip] = domain
                                            session['domain'] = domain
                                            count += 1
                                        else:
                                            # Try alternative domain resolution methods
                                            self._try_alternate_domain_resolution(dst_ip, session)
                                            count += 1
                                    else:
                                        # Try alternative domain resolution methods
                                        self._try_alternate_domain_resolution(dst_ip, session)
                                        count += 1
                                except Exception:
                                    # Try alternative domain resolution methods
                                    self._try_alternate_domain_resolution(dst_ip, session)
                                    count += 1
                    except Exception:
                        pass
                
                # Clean up stale domain cache entries periodically
                if hasattr(self, '_last_domain_cleanup'):
                    if time.time() - self._last_domain_cleanup > 3600:  # Once per hour
                        self._cleanup_domain_cache()
                else:
                    self._last_domain_cleanup = time.time()
                
            except Exception as e:
                logging.debug(f"Error resolving domains: {e}")
    
    def _try_alternate_domain_resolution(self, ip, session):
        """Try alternative methods to resolve domains when standard PTR lookup fails"""
        try:
            # Try to find domain from application data
            for app_name, app_data in self.stats['applications'].items():
                if app_name != 'Unknown':
                    # Check if this app has domains and this IP in its connections
                    if app_data['domains'] and session.get('process') == app_name:
                        # Use the first domain associated with this app
                        domain = next(iter(app_data['domains']))
                        self.dns_cache[ip] = domain
                        session['domain'] = domain
                return True
            
            # Check if there are any HTTP/HTTPS sessions with the same IP but known domains
            for other_key, other_session in self.stats['sessions'].items():
                if ('domain' in other_session and 
                    other_session['domain'] != 'Unknown' and 
                    other_session['dst_ip'] == ip):
                    self.dns_cache[ip] = other_session['domain']
                    session['domain'] = other_session['domain']
                    return True
                    
            # If no domain found, mark as Unknown but don't give up completely
            if ip not in self.dns_cache or self.dns_cache[ip] is None:
                self.dns_cache[ip] = "Unknown"
                session['domain'] = "Unknown"
            return False
        except Exception as e:
            logging.debug(f"Error in alternative domain resolution: {e}")
            if ip not in self.dns_cache:
                self.dns_cache[ip] = "Unknown"
                session['domain'] = "Unknown"
            return False
    
    def _cleanup_domain_cache(self):
        """Clean up old or stale domain cache entries"""
        try:
            # Remove domains for IPs that haven't been seen in a while
            current_ips = set()
            for session in self.stats['sessions'].values():
                if 'dst_ip' in session:
                    current_ips.add(session['dst_ip'])
            
            # Remove cache entries for IPs not in active sessions
            for ip in list(self.dns_cache.keys()):
                if ip not in current_ips:
                    del self.dns_cache[ip]
            
            self._last_domain_cleanup = time.time()
        except Exception as e:
            logging.debug(f"Error cleaning domain cache: {e}")
    
    def _print_stats(self):
        """Print statistics periodically for debugging"""
        last_time = time.time()
        last_packets = 0
        last_bytes = 0
        
        while not self.stop_flag.is_set():
            try:
                # Wait a bit
                time.sleep(5)
                
                # Calculate rates
                now = time.time()
                elapsed = now - last_time
                
                if elapsed > 0:
                    # Calculate rates
                    packets_rate = (self.stats['total_packets'] - last_packets) / elapsed
                    bytes_rate = (self.stats['total_bytes'] - last_bytes) / elapsed
                    
                    # Log statistics
                    logging.info(f"Traffic: {packets_rate:.1f} packets/sec, {bytes_rate/1024:.1f} KB/sec")
                    
                    # Top 5 active sessions
                    active_sessions = sorted(
                        self.stats['sessions'].values(),
                        key=lambda x: x['last_time'],
                        reverse=True
                    )[:5]
                    
                    for session in active_sessions:
                        logging.info(f"Session: {session['src_ip']}:{session['src_port']} -> "
                                    f"{session['dst_ip']}:{session['dst_port']} ({session['protocol']}) - "
                                    f"{session['bytes']/1024:.1f} KB - "
                                    f"Process: {session['process']}")
                    
                    # Clean up old sessions
                    self._cleanup_old_sessions()
                    
                    # Update previous values
                    last_time = now
                    last_packets = self.stats['total_packets']
                    last_bytes = self.stats['total_bytes']
            
            except Exception as e:
                logging.error(f"Error printing stats: {e}")
    
    def _cleanup_old_sessions(self):
        """Clean up old sessions to prevent memory growth"""
        # Remove sessions older than 5 minutes
        now = time.time()
        cutoff = now - 300  # 5 minutes
        
        for key in list(self.stats['sessions'].keys()):
            if self.stats['sessions'][key]['last_time'] < cutoff:
                del self.stats['sessions'][key]
    
    def stop_capture(self):
        """Stop capturing packets"""
        try:
            # Set stop flag to stop all threads
            self.stop_flag.set()
            
            # Wait for threads to finish
            if hasattr(self, 'capture_thread') and self.capture_thread:
                self.capture_thread.join(timeout=1.0)
            if hasattr(self, 'analysis_thread') and self.analysis_thread:
                self.analysis_thread.join(timeout=1.0)
            if hasattr(self, 'stats_thread') and self.stats_thread:
                self.stats_thread.join(timeout=1.0)
            if hasattr(self, 'dns_thread') and self.dns_thread:
                self.dns_thread.join(timeout=1.0)
            
            # Close GeoIP readers
            if hasattr(self, 'geoip_city') and self.geoip_city:
                self.geoip_city.close()
            if hasattr(self, 'geoip_country') and self.geoip_country:
                self.geoip_country.close()
            
            return True
        except Exception as e:
            logging.error(f"Error stopping capture: {e}")
            return False
    
    def get_statistics(self):
        """Get current statistics"""
        return self.stats
    
    def get_application_traffic(self):
        """Get application traffic statistics"""
        return self.app_traffic
    
    def get_geo_data(self):
        """Get geolocation data"""
        return {
            'connections': self.stats['geo_connections'],
            'countries': self.stats['countries']
        }
    
    def get_process_info(self, pid):
        """Get process information for a given PID"""
        try:
            # Return cached result if available (and not Unknown)
            if pid in self.process_cache and self.process_cache[pid]['name'] != 'Unknown':
                # Only use cache for non-Unknown process info
                return self.process_cache[pid]

            process = None
            # Try to get process info from psutil
            try:
                process = psutil.Process(pid)
                
                # Get process executable and name
                try:
                    exe = process.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess, FileNotFoundError):
                    exe = "Access Denied"
                
                # Get process name, falling back to exe basename if needed
                try:
                    name = process.name()
                    if not name and exe != "Access Denied":
                        name = os.path.basename(exe)
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    if exe != "Access Denied" and exe:
                        name = os.path.basename(exe)
                    else:
                        name = f"PID {pid}"
                
                # Get command line if possible
                try:
                    cmdline = " ".join(process.cmdline())
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    cmdline = "Access Denied"
                
                # Get username if possible
                try:
                    username = process.username()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    username = "Unknown"
                
                # Get create time if possible
                try:
                    create_time = datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S')
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    create_time = "Unknown"
                
                # Check for Windows service association using SC query
                service_name = self._check_service_for_pid(pid)
                
                # Create process information dictionary
                process_info = {
                    'pid': pid,
                    'name': name,
                    'exe': exe,
                    'cmdline': cmdline,
                    'username': username,
                    'create_time': create_time,
                    'service': service_name
                }
                
                # Cache result
                self.process_cache[pid] = process_info
                return process_info
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                # Process no longer exists or access denied
                if isinstance(e, psutil.NoSuchProcess):
                    self.logger.debug(f"Process {pid} no longer exists")
                elif isinstance(e, psutil.AccessDenied):
                    self.logger.debug(f"Access denied for process {pid}")
                else:
                    self.logger.debug(f"Zombie process {pid}")
                
                # Try to get from Windows netstat -b output as fallback
                fallback_info = self._get_process_from_netstat_or_netsh(pid)
                if fallback_info:
                    # Cache result
                    self.process_cache[pid] = fallback_info
                    return fallback_info
                
                # Use generic info if all else fails
                generic_info = {
                    'pid': pid,
                    'name': f"Unknown Process {pid}",
                    'exe': "Unknown",
                    'cmdline': "",
                    'username': "Unknown",
                    'create_time': "Unknown",
                    'service': ""
                }
                
                # Only cache negative results temporarily
                self.process_cache[pid] = generic_info
                return generic_info
                
        except Exception as e:
            self.logger.error(f"Error getting process info for PID {pid}: {e}")
            return {
                'pid': pid,
                'name': 'Error',
                'exe': f"Error: {str(e)}",
                'cmdline': "",
                'username': "Unknown",
                'create_time': "Unknown",
                'service': ""
            }
            
    def _check_service_for_pid(self, pid):
        """Use SC query to find services associated with the PID"""
        try:
            # Only run on Windows
            if os.name != 'nt':
                return ""
                
            # This command only works with admin rights
            if not self.is_admin:
                return ""
                
            # We'll limit how often we run this to avoid performance impact
            if not hasattr(self, 'last_sc_query_time'):
                self.last_sc_query_time = 0
                
            current_time = time.time()
            if current_time - self.last_sc_query_time < 60:  # Only run once per minute max
                return ""
                
            self.last_sc_query_time = current_time
            
            # Run SC query to get all services
            output = subprocess.check_output(
                ["sc", "queryex", "type=service", "state=all"], 
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=5
            )
            
            # Parse output looking for PID matches
            service_name = None
            current_service = None
            
            for line in output.splitlines():
                if "SERVICE_NAME" in line:
                    current_service = line.split(":", 1)[1].strip()
                elif "PID" in line and f" {pid}" in line:
                    service_name = current_service
                    break
            
            return service_name or ""
            
        except Exception as e:
            self.logger.debug(f"Error checking service for PID {pid}: {e}")
            return ""
            
    def _get_process_from_netstat_or_netsh(self, pid):
        """Use netstat -b or netsh to try to get process name for a PID"""
        try:
            # Only run on Windows
            if os.name != 'nt':
                return None
                
            # Limit how often we run netstat to avoid performance issues
            if not hasattr(self, 'last_netstat_time'):
                self.last_netstat_time = 0
                
            current_time = time.time()
            if current_time - self.last_netstat_time < 30:  # Only run once per 30 seconds max
                return None
                
            self.last_netstat_time = current_time
            
            # Try netstat -b first (requires admin)
            if self.is_admin:
                try:
                    # Command succeeds only with admin rights
                    output = subprocess.check_output(
                        ["netstat", "-b", "-n", "-o"], 
                        stderr=subprocess.STDOUT,
                        universal_newlines=True,
                        timeout=5
                    )
                    
                    # Parse output to find the PID
                    lines = output.splitlines()
                    for i, line in enumerate(lines):
                        if f" {pid}" in line:
                            # Process name is usually in the next line in square brackets
                            if i + 1 < len(lines) and "[" in lines[i+1] and "]" in lines[i+1]:
                                process_name = lines[i+1].strip()[1:-1]  # Remove brackets
                                return {
                                    'pid': pid,
                                    'name': process_name,
                                    'exe': process_name,
                                    'cmdline': "",
                                    'username': "Unknown",
                                    'create_time': "Unknown",
                                    'service': ""
                                }
                except Exception as e:
                    self.logger.debug(f"Error running netstat -b: {e}")
            
            # Try netsh as fallback (less info but may work without admin)
            try:
                output = subprocess.check_output(
                    ["netsh", "interface", "ipv4", "show", "tcpconnections"], 
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    timeout=5
                )
                
                # Parse output to find the PID and app
                for line in output.splitlines():
                    if f" {pid} " in line:
                        parts = line.strip().split()
                        if len(parts) >= 5:
                            # Last column might have process info
                            process_info = parts[-1]
                            if process_info.lower() != "unknown":
                                return {
                                    'pid': pid,
                                    'name': process_info,
                                    'exe': process_info,
                                    'cmdline': "",
                                    'username': "Unknown",
                                    'create_time': "Unknown",
                                    'service': ""
                                }
            except Exception as e:
                self.logger.debug(f"Error running netsh: {e}")
                
            return None
            
        except Exception as e:
            self.logger.debug(f"Error getting process from netstat/netsh: {e}")
            return None 