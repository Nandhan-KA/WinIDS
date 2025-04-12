#!/usr/bin/env python
"""
Manual fix for potential syntax errors in MacIDS network_monitor.py
"""
import os
import sys
import shutil

def fix_network_monitor():
    try:
        # Define the path to network_monitor.py
        file_path = os.path.join('macids', 'netmon', 'network_monitor.py')
        
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
        
        # Check if any changes were made
        if new_content == original_content:
            print("No changes needed - network_monitor.py is already correctly formatted")
            # Remove the backup if no changes were needed
            os.remove(backup_path)
            return True
        
        # Write the fixed content back to the file
        with open(file_path, 'w') as f:
            f.write(new_content)
        
        print(f"Successfully fixed {file_path}")
        return True
    
    except Exception as e:
        print(f"Error fixing network_monitor.py: {e}")
        return False

def update_version():
    """Update version number in setup.py from 1.2 to 1.3"""
    try:
        # Path to setup.py
        setup_path = 'setup.py'
        
        # Read current content
        with open(setup_path, 'r') as f:
            content = f.read()
        
        # Update version from 1.2 to 1.3
        updated_content = content.replace('version="1.2"', 'version="1.3"')
        
        # Check if any changes were made
        if updated_content == content:
            print("Version is already 1.3 or not found in expected format")
            return True
        
        # Write the updated content
        with open(setup_path, 'w') as f:
            f.write(updated_content)
        
        print("Successfully updated version from 1.2 to 1.3 in setup.py")
        return True
        
    except Exception as e:
        print(f"Error updating version in setup.py: {e}")
        return False

def main():
    print("MacIDS Fix Script")
    print("----------------")
    
    # Fix the network_monitor.py file
    print("\nChecking network_monitor.py...")
    fix_result = fix_network_monitor()
    
    # Update version number
    print("\nUpdating version number...")
    version_result = update_version()
    
    if fix_result and version_result:
        print("\nAll fixes applied successfully!")
        print("\nYou can now rebuild the package with:")
        print("python -m build")
        print("\nAnd install it with:")
        print("pip install --force-reinstall dist/macids-1.3-py3-none-any.whl")
    else:
        print("\nSome fixes were not applied successfully. Please check the errors above.")
    
    return 0 if (fix_result and version_result) else 1

if __name__ == "__main__":
    sys.exit(main()) 