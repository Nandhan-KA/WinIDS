#!/usr/bin/env python
"""
Manual fix for the syntax error in network_monitor.py
"""
import os
import sys

def fix_network_monitor():
    try:
        # Define the path to network_monitor.py
        file_path = os.path.join('WinIDS', 'netmon', 'network_monitor.py')
        
        # Check if the file exists
        if not os.path.exists(file_path):
            print(f"Error: {file_path} not found")
            return False
        
        # Create a backup
        backup_path = file_path + '.bak'
        with open(file_path, 'r') as f:
            original_content = f.read()
        
        with open(backup_path, 'w') as f:
            f.write(original_content)
        print(f"Created backup at {backup_path}")
        
        # Define the corrected _init_geoip method
        corrected_method = '''    def _init_geoip(self):
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
            logging.error(f"Failed to initialize GeoIP database: {e}")
            logging.info("Using fallback for GeoIP lookups - location data will be limited")
'''
        
        # Find the start and end of the _init_geoip method
        start_marker = '    def _init_geoip(self):'
        end_marker = '    def get_ip_location(self, ip):'
        
        # Replace the method in the content
        start_index = original_content.find(start_marker)
        end_index = original_content.find(end_marker)
        
        if start_index == -1 or end_index == -1:
            print("Error: Could not find the _init_geoip method in the file")
            return False
        
        new_content = (
            original_content[:start_index] + 
            corrected_method + 
            original_content[end_index:]
        )
        
        # Write the fixed content back to the file
        with open(file_path, 'w') as f:
            f.write(new_content)
        
        print(f"Successfully fixed {file_path}")
        return True
    
    except Exception as e:
        print(f"Error fixing network_monitor.py: {e}")
        return False

if __name__ == "__main__":
    if fix_network_monitor():
        print("Fix completed successfully")
        sys.exit(0)
    else:
        print("Fix failed")
        sys.exit(1) 