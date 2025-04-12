import os
import requests
import tarfile
import shutil
import tempfile
import sys
from pathlib import Path

def download_geolite2_db():
    """
    Downloads the free GeoLite2 City database for IP geolocation
    Note: MaxMind requires a license key for their GeoLite2 database.
    This script uses a free alternative database provider.
    """
    print("Setting up GeoIP database for network analyzer...")
    
    # Create directory if it doesn't exist
    db_dir = Path("geoip_db")
    db_dir.mkdir(exist_ok=True)
    
    # Target file paths
    city_db_path = db_dir / "GeoLite2-City.mmdb"
    country_db_path = db_dir / "GeoLite2-Country.mmdb"
    
    # Check if files already exist
    if city_db_path.exists() and country_db_path.exists():
        print("GeoIP databases already exist. Skipping download.")
        return str(city_db_path), str(country_db_path)
    
    # URLs for GeoLite2 databases from free sources
    city_db_url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
    country_db_url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
    
    try:
        # Download City Database
        print("Downloading GeoLite2 City database...")
        response = requests.get(city_db_url, stream=True)
        response.raise_for_status()
        
        with open(city_db_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        # Download Country Database
        print("Downloading GeoLite2 Country database...")
        response = requests.get(country_db_url, stream=True)
        response.raise_for_status()
        
        with open(country_db_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        print(f"GeoIP databases downloaded successfully to {db_dir}")
        return str(city_db_path), str(country_db_path)
    
    except Exception as e:
        print(f"Error downloading GeoIP database: {e}")
        sys.exit(1)

if __name__ == "__main__":
    city_db, country_db = download_geolite2_db()
    print(f"City database: {city_db}")
    print(f"Country database: {country_db}") 