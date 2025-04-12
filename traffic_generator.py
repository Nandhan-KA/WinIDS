#!/usr/bin/env python
"""
Simple traffic generator script for testing the WinIDS Network Analyzer.
This will generate HTTP requests, DNS lookups, and ping requests to test the connection monitoring.
"""

import os
import sys
import time
import subprocess
import threading
import random
import socket
import requests

def generate_http_requests():
    """Generate HTTP requests to random popular websites"""
    websites = [
        "www.google.com",
        "www.youtube.com",
        "www.facebook.com",
        "www.twitter.com",
        "www.amazon.com",
        "www.wikipedia.org",
        "www.reddit.com",
        "www.instagram.com",
        "www.netflix.com",
        "www.github.com"
    ]
    
    print("Starting HTTP requests...")
    for _ in range(10):  # Make 10 requests
        site = random.choice(websites)
        try:
            print(f"Making HTTP request to {site}...")
            response = requests.get(f"https://{site}", timeout=5)
            print(f"Response from {site}: {response.status_code}")
        except Exception as e:
            print(f"Error connecting to {site}: {e}")
        
        # Sleep between requests
        time.sleep(1.5)
    print("Finished HTTP requests")

def generate_dns_lookups():
    """Generate DNS lookups to random domains"""
    domains = [
        "example.com",
        "python.org",
        "microsoft.com",
        "apple.com",
        "cloudflare.com",
        "github.io",
        "amazonaws.com"
    ]
    
    print("Starting DNS lookups...")
    for _ in range(7):  # Make 7 lookups
        domain = random.choice(domains)
        try:
            print(f"Looking up {domain}...")
            ip_address = socket.gethostbyname(domain)
            print(f"IP address for {domain}: {ip_address}")
        except Exception as e:
            print(f"Error looking up {domain}: {e}")
        
        # Sleep between lookups
        time.sleep(2)
    print("Finished DNS lookups")

def generate_ping_requests():
    """Generate ping requests to random DNS servers"""
    dns_servers = [
        "8.8.8.8",  # Google DNS
        "1.1.1.1",  # Cloudflare DNS
        "9.9.9.9",  # Quad9 DNS
        "208.67.222.222",  # OpenDNS
        "64.6.64.6"  # Verisign DNS
    ]
    
    print("Starting ping requests...")
    for _ in range(5):  # Make 5 ping requests
        dns_server = random.choice(dns_servers)
        try:
            print(f"Pinging {dns_server}...")
            # Use -n 4 to send 4 pings on Windows
            subprocess.run(["ping", "-n", "4", dns_server], check=True, capture_output=True)
            print(f"Finished pinging {dns_server}")
        except Exception as e:
            print(f"Error pinging {dns_server}: {e}")
        
        # Sleep between pings
        time.sleep(2)
    print("Finished ping requests")

def main():
    """Main function to generate traffic"""
    print("Starting traffic generator...")
    
    # Create threads for different traffic types
    http_thread = threading.Thread(target=generate_http_requests)
    dns_thread = threading.Thread(target=generate_dns_lookups)
    ping_thread = threading.Thread(target=generate_ping_requests)
    
    # Start the threads
    http_thread.start()
    dns_thread.start()
    ping_thread.start()
    
    # Wait for all threads to complete
    http_thread.join()
    dns_thread.join()
    ping_thread.join()
    
    print("All traffic generation completed!")

if __name__ == "__main__":
    main() 