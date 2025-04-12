"""
GeoIP Database Downloader for MacIDS

This module downloads the MaxMind GeoLite2 database files required for geolocation.
"""

import os
import sys
import logging
import requests
import tarfile
import shutil
from pathlib import Path

logger = logging.getLogger("macids.netmon.geoip")

# Default paths
DEFAULT_DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "geoip_db")
DEFAULT_CITY_DB = os.path.join(DEFAULT_DB_DIR, "GeoLite2-City.mmdb")
DEFAULT_COUNTRY_DB = os.path.join(DEFAULT_DB_DIR, "GeoLite2-Country.mmdb")

# MaxMind download URLs - using dummy links since actual ones require an account
# Users need to replace these with their own or use pre-downloaded databases
GEOLITE2_CITY_URL = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_LICENSE_KEY&suffix=tar.gz"
GEOLITE2_COUNTRY_URL = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=YOUR_LICENSE_KEY&suffix=tar.gz"

def download_geolite2_db(force=False):
    """
    Download and extract GeoLite2 City and Country databases
    
    Args:
        force (bool): Force download even if files exist
        
    Returns:
        tuple: (city_db_path, country_db_path)
    """
    city_db_path = DEFAULT_CITY_DB
    country_db_path = DEFAULT_COUNTRY_DB
    
    # Check if files already exist
    if not force and os.path.exists(city_db_path) and os.path.exists(country_db_path):
        logger.info("GeoIP database files already exist, skipping download")
        return city_db_path, country_db_path
    
    # Create directory if it doesn't exist
    os.makedirs(DEFAULT_DB_DIR, exist_ok=True)
    
    # Check for macOS-specific system paths for GeoIP
    system_paths = [
        "/usr/local/share/GeoIP",
        "/usr/share/GeoIP",
        "/usr/local/var/GeoIP",
        "/opt/homebrew/var/GeoIP"
    ]
    
    for path in system_paths:
        city_path = os.path.join(path, "GeoLite2-City.mmdb")
        country_path = os.path.join(path, "GeoLite2-Country.mmdb")
        
        if os.path.exists(city_path) and os.path.exists(country_path):
            logger.info(f"Found system GeoIP databases in {path}")
            
            # Copy to our directory
            try:
                shutil.copy2(city_path, city_db_path)
                shutil.copy2(country_path, country_db_path)
                logger.info("Copied system GeoIP databases to local directory")
                return city_db_path, country_db_path
            except (IOError, PermissionError) as e:
                logger.warning(f"Failed to copy system databases: {e}")
                # Continue to download attempt
    
    logger.warning("This application requires MaxMind GeoLite2 databases")
    logger.warning("You need to download them manually from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
    logger.warning(f"Place the .mmdb files in: {DEFAULT_DB_DIR}")
    
    # Check if files exist after user might have placed them
    if os.path.exists(city_db_path) and os.path.exists(country_db_path):
        logger.info("GeoIP database files found")
        return city_db_path, country_db_path
    
    # Return the paths even if download failed
    # The calling code should handle missing files
    return city_db_path, country_db_path

if __name__ == "__main__":
    # Set up logging when run directly
    logging.basicConfig(level=logging.INFO, 
                      format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    
    # Download databases
    city_path, country_path = download_geolite2_db(force=True)
    print(f"City database: {city_path}")
    print(f"Country database: {country_path}") 