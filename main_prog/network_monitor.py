import scapy.all as scapy
from scapy.layers import http
import pandas as pd
import numpy as np
from datetime import datetime
import threading
import queue
import time
import json
import os
import logging
from collections import defaultdict
import pydivert
import socket
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTP
import struct
import psutil
import dns.resolver
import dns.reversename
import geoip2.database
import ipaddress
from pathlib import Path

# Import GeoIP database downloader
try:
    from download_geoip_db import download_geolite2_db
except ImportError:
    # Define a minimal version if the module is not available
    def download_geolite2_db():
        print("GeoIP database downloader not available. Using default paths.")
        return "geoip_db/GeoLite2-City.mmdb", "geoip_db/GeoLite2-Country.mmdb"

class SystemNetworkMonitor:
    def __init__(self, interface="0", port=0):
        self.interface = interface
        self.port = port
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

    def _init_geoip(self):
        """Initialize GeoIP database for IP location lookup"""
        try:
            # Download GeoIP database if needed
            city_db_path, country_db_path = download_geolite2_db()
            
            # Open GeoIP readers
            self.geoip_city = geoip2.database.Reader(city_db_path)
            self.geoip_country = geoip2.database.Reader(country_db_path)
            logging.info(f"Initialized GeoIP database from {city_db_path}")
        except Exception as e:
            logging.error(f"Failed to initialize GeoIP database: {e}")
            self.geoip_city = None
            self.geoip_country = None

    def get_ip_location(self, ip):
        """Get location information for an IP address"""
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        
        # Skip private IP addresses
        try:
            if ipaddress.ip_address(ip).is_private:
                self.geo_cache[ip] = {
                    'country': 'Private',
                    'country_code': 'XX',
                    'city': 'Private Network',
                    'latitude': 0,
                    'longitude': 0
                }
                return self.geo_cache[ip]
        except:
            # If IP parsing fails, return unknown
            self.geo_cache[ip] = {
                'country': 'Unknown',
                'country_code': 'XX',
                'city': 'Unknown',
                'latitude': 0,
                'longitude': 0
            }
            return self.geo_cache[ip]
        
        # Lookup location
        try:
            if self.geoip_city:
                response = self.geoip_city.city(ip)
                location = {
                    'country': response.country.name or 'Unknown',
                    'country_code': response.country.iso_code or 'XX',
                    'city': response.city.name or 'Unknown',
                    'latitude': response.location.latitude or 0,
                    'longitude': response.location.longitude or 0
                }
                self.geo_cache[ip] = location
                return location
        except Exception as e:
            # If lookup fails, return unknown
            logging.debug(f"GeoIP lookup failed for {ip}: {e}")
            self.geo_cache[ip] = {
                'country': 'Unknown',
                'country_code': 'XX',
                'city': 'Unknown',
                'latitude': 0,
                'longitude': 0
            }
            return self.geo_cache[ip]

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
                    
                    # Update basic statistics
                    self.stats['total_packets'] += 1
                    self.stats['total_bytes'] += len(raw_data)
                    
                    # Find associated process
                    process_info = self._get_process_by_connection(packet)
                    
                    # Analyze packet details
                    self._analyze_packet_details(scapy_packet, packet, raw_data, process_info)
                except Exception as e:
                    # Handle parsing errors
                    logging.error(f"Error parsing packet: {e}")
                
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Error analyzing packet: {e}")

    def _get_process_by_connection(self, packet):
        """Try to identify the process responsible for this connection"""
        try:
            # Extract connection details from the packet
            if hasattr(packet, 'src_addr') and hasattr(packet, 'dst_addr') and \
               hasattr(packet, 'src_port') and hasattr(packet, 'dst_port'):
                
                local_ip = packet.src_addr
                local_port = packet.src_port
                remote_ip = packet.dst_addr
                remote_port = packet.dst_port
                
                # Check if this is an outgoing packet
                is_outgoing = not packet.is_inbound
                
                if is_outgoing:
                    # For outgoing packets, check local port
                    conn_key = (local_ip, local_port)
                else:
                    # For incoming packets, check remote port connection
                    conn_key = (local_ip, local_port)
                
                # Try to find the process
                for conn in psutil.net_connections(kind='inet'):
                    if conn.laddr and len(conn.laddr) == 2:  # Ensure laddr has IP and port
                        if conn.laddr.port == conn_key[1] and (conn.laddr.ip == conn_key[0] or conn.laddr.ip == '0.0.0.0' or conn.laddr.ip == '::'):
                            if conn.pid:
                                try:
                                    process = psutil.Process(conn.pid)
                                    return {
                                        'pid': conn.pid,
                                        'name': process.name(),
                                        'exe': process.exe() if hasattr(process, 'exe') else "Unknown",
                                        'local_ip': local_ip,
                                        'local_port': local_port,
                                        'remote_ip': remote_ip,
                                        'remote_port': remote_port
                                    }
                                except psutil.NoSuchProcess:
                                    pass
            
            return None
        except Exception as e:
            logging.error(f"Error getting process info: {e}")
            return None

    def _analyze_packet_details(self, scapy_packet, original_packet, raw_data, process_info):
        """Analyze detailed packet information"""
        try:
            # Get IP information
            if IP in scapy_packet:
                src_ip = scapy_packet[IP].src
                dst_ip = scapy_packet[IP].dst
                protocol = scapy_packet[IP].proto
                
                # Queue DNS resolution for destination IP
                if dst_ip not in self.dns_cache and dst_ip != '127.0.0.1' and not dst_ip.startswith('192.168.') and not dst_ip.startswith('10.'):
                    self.dns_cache[dst_ip] = None  # Mark as "resolution in progress"
                
                # Get geolocation for external IPs
                if not dst_ip.startswith('192.168.') and not dst_ip.startswith('10.') and dst_ip != '127.0.0.1':
                    dst_location = self.get_ip_location(dst_ip)
                    # Update country statistics
                    if dst_location and 'country' in dst_location:
                        self.stats['countries'][dst_location['country']] += 1
                
                # Track geolocation data for connections
                try:
                    # Only process external connections (not local network)
                    if not dst_ip.startswith('192.168.') and not dst_ip.startswith('10.') and dst_ip != '127.0.0.1':
                        src_location = self.get_ip_location(src_ip)
                        dst_location = self.get_ip_location(dst_ip)
                        
                        # Create a connection record with geo data
                        geo_conn = {
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': original_packet.src_port,
                            'dst_port': original_packet.dst_port,
                            'protocol': protocol,
                            'bytes': len(raw_data),
                            'timestamp': time.time(),
                            'src_country': src_location['country'],
                            'src_country_code': src_location['country_code'],
                            'src_city': src_location['city'],
                            'src_lat': src_location['latitude'],
                            'src_lon': src_location['longitude'],
                            'dst_country': dst_location['country'],
                            'dst_country_code': dst_location['country_code'],
                            'dst_city': dst_location['city'],
                            'dst_lat': dst_location['latitude'],
                            'dst_lon': dst_location['longitude'],
                            'app_name': process_info['name'] if process_info else "Unknown"
                        }
                        
                        # Keep only 1000 most recent connections to avoid memory issues
                        self.stats['geo_connections'].append(geo_conn)
                        if len(self.stats['geo_connections']) > 1000:
                            self.stats['geo_connections'] = self.stats['geo_connections'][-1000:]
                except Exception as e:
                    logging.error(f"Error processing geolocation: {e}")
                
                # Update protocol statistics
                self.stats['protocols'][protocol] += 1
                
                # Track application usage if process info is available
                if process_info:
                    app_name = process_info['name']
                    
                    # Update application statistics
                    self.stats['applications'][app_name]['bytes'] += len(raw_data)
                    conn_string = f"{src_ip}:{original_packet.src_port}-{dst_ip}:{original_packet.dst_port}"
                    self.stats['applications'][app_name]['connections'].add(conn_string)
                    
                    # Track domains for this application if we have resolved the IP
                    if dst_ip in self.dns_cache and self.dns_cache[dst_ip]:
                        self.stats['applications'][app_name]['domains'].add(self.dns_cache[dst_ip])
                
                # TCP analysis
                if TCP in scapy_packet:
                    src_port = scapy_packet[TCP].sport
                    dst_port = scapy_packet[TCP].dport
                    flags = scapy_packet[TCP].flags
                    
                    # Track TCP session
                    session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    self.stats['sessions'][session_key] = {
                        'protocol': 'TCP',
                        'start_time': time.time(),
                        'bytes': len(raw_data),
                        'flags': flags,
                        'app_name': process_info['name'] if process_info else "Unknown",
                        'domain': self.dns_cache.get(dst_ip, "Unknown"),
                        'geo': self.get_ip_location(dst_ip)  # Add geolocation data
                    }
                    
                    # Update port statistics
                    self.stats['ports'][src_port] += 1
                    self.stats['ports'][dst_port] += 1
                    
                    # For HTTP traffic (ports 80, 443, 8080, etc.)
                    if dst_port in (80, 443, 8080, 8443):
                        if dst_ip in self.dns_cache and self.dns_cache[dst_ip]:
                            # Update domain statistics
                            self.stats['domains'][self.dns_cache[dst_ip]] += 1
                
                # UDP analysis
                elif UDP in scapy_packet:
                    src_port = scapy_packet[UDP].sport
                    dst_port = scapy_packet[UDP].dport
                    
                    # Track UDP flow
                    flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    self.stats['sessions'][flow_key] = {
                        'protocol': 'UDP',
                        'start_time': time.time(),
                        'bytes': len(raw_data),
                        'app_name': process_info['name'] if process_info else "Unknown",
                        'domain': self.dns_cache.get(dst_ip, "Unknown"),
                        'geo': self.get_ip_location(dst_ip)  # Add geolocation data
                    }
                    
                    # Update port statistics
                    self.stats['ports'][src_port] += 1
                    self.stats['ports'][dst_port] += 1
                    
                    # DNS traffic (port 53)
                    if dst_port == 53 or src_port == 53:
                        # Could parse DNS queries here if needed
                        pass
                
                # Track connections
                conn_key = f"{src_ip}-{dst_ip}"
                self.stats['connections'][conn_key] += 1
                
        except Exception as e:
            logging.error(f"Error in packet analysis: {e}")

    def _resolve_domains(self):
        """Background thread to resolve IP addresses to domain names"""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1
        resolver.lifetime = 1
        
        while not self.stop_flag.is_set():
            try:
                # Find IPs that need resolution
                ips_to_resolve = [ip for ip, domain in self.dns_cache.items() if domain is None]
                
                for ip in ips_to_resolve[:10]:  # Process in small batches
                    try:
                        # Try PTR lookup
                        addr = dns.reversename.from_address(ip)
                        answers = resolver.resolve(addr, "PTR")
                        if answers:
                            self.dns_cache[ip] = str(answers[0]).rstrip('.')
                        else:
                            self.dns_cache[ip] = ip  # Use IP if no domain found
                    except Exception:
                        # If reverse lookup fails, use the IP address
                        self.dns_cache[ip] = ip
            except Exception as e:
                logging.error(f"Error in DNS resolution: {e}")
            
            time.sleep(5)  # Sleep before next batch

    def _print_stats(self):
        """Print periodic statistics"""
        while not self.stop_flag.is_set():
            try:
                print("\n=== System Network Traffic Statistics ===")
                print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"Total Packets: {self.stats['total_packets']}")
                print(f"Total Traffic: {self.stats['total_bytes']/1024/1024:.2f} MB")
                
                # Protocol distribution
                print("\nProtocol Distribution:")
                for proto, count in self.stats['protocols'].items():
                    try:
                        proto_name = socket.getprotocol(proto)
                    except:
                        proto_name = f"Protocol {proto}"
                    print(f"  {proto_name}: {count} packets")
                
                # Top ports
                print("\nTop Active Ports:")
                sorted_ports = sorted(self.stats['ports'].items(), 
                                   key=lambda x: x[1], reverse=True)[:10]
                for port, count in sorted_ports:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "Unknown"
                    print(f"  Port {port} ({service}): {count} packets")
                
                # Active connections
                print("\nActive Connections:")
                active_conns = sorted(self.stats['connections'].items(), 
                                   key=lambda x: x[1], reverse=True)[:10]
                for conn, count in active_conns:
                    print(f"  {conn}: {count} packets")
                
                # Applications
                print("\nApplications:")
                sorted_apps = sorted(self.stats['applications'].items(), 
                                  key=lambda x: x[1]['bytes'], reverse=True)[:10]
                for app, stats in sorted_apps:
                    domains_str = ", ".join(list(stats['domains'])[:3])
                    print(f"  {app}: {stats['bytes']/1024:.2f} KB - Domains: {domains_str}")
                
                # Countries
                print("\nTop Countries:")
                sorted_countries = sorted(self.stats['countries'].items(),
                                       key=lambda x: x[1], reverse=True)[:10]
                for country, count in sorted_countries:
                    print(f"  {country}: {count} packets")
                
                # Clean up old sessions
                self._cleanup_old_sessions()
                
                print("=" * 40)
                
            except Exception as e:
                logging.error(f"Error printing statistics: {e}")
            
            time.sleep(10)  # Update every 10 seconds

    def _cleanup_old_sessions(self):
        """Clean up old session entries"""
        current_time = time.time()
        session_timeout = 300  # 5 minutes
        
        for session_key in list(self.stats['sessions'].keys()):
            session = self.stats['sessions'][session_key]
            if current_time - session['start_time'] > session_timeout:
                del self.stats['sessions'][session_key]

    def stop_capture(self):
        """Stop the network capture"""
        self.stop_flag.set()
        if hasattr(self, 'capture_thread'):
            self.capture_thread.join()
        if hasattr(self, 'analysis_thread'):
            self.analysis_thread.join()
        if hasattr(self, 'stats_thread'):
            self.stats_thread.join()
        if hasattr(self, 'dns_thread'):
            self.dns_thread.join()
        
        # Close GeoIP database readers
        if hasattr(self, 'geoip_city') and self.geoip_city:
            self.geoip_city.close()
        if hasattr(self, 'geoip_country') and self.geoip_country:
            self.geoip_country.close()
            
        logging.info("Stopped network monitoring")

    def get_statistics(self):
        """Return current statistics"""
        return self.stats

    def get_application_traffic(self):
        """Return application traffic statistics"""
        return {
            'applications': self.stats['applications'],
            'domains': self.stats['domains']
        }
        
    def get_geo_data(self):
        """Return geolocation data"""
        return {
            'countries': self.stats['countries'],
            'connections': self.stats['geo_connections']
        }

if __name__ == "__main__":
    monitor = SystemNetworkMonitor()
    
    try:
        if monitor.start_capture():
            print("\nMonitoring system network traffic...")
            print("Press Ctrl+C to stop")
            
            while True:
                time.sleep(1)
                
    except KeyboardInterrupt:
        print("\nStopping network monitoring...")
        monitor.stop_capture() 