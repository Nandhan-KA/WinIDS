import re

def fix_indentation(input_file, output_file):
    # Read the file
    with open(input_file, 'r') as f:
        content = f.read()
    
    # Fix if CARTOPY_AVAILABLE blocks
    content = re.sub(r'(\s+)if CARTOPY_AVAILABLE:\s*\n\s+(\S+)', r'\1if CARTOPY_AVAILABLE:\n\1    \2', content)
    
    # Fix the map canvas indentation
    content = re.sub(r'(\s+# Create canvas\s*\n\s+)self\.map_canvas', r'\1            self.map_canvas', content)
    content = re.sub(r'(\s+self\.map_canvas\.draw\(\)\s*\n\s+)self\.map_canvas', r'\1            self.map_canvas', content)
    content = re.sub(r'(\s+self\.map_canvas\.get_tk_widget\(\)\.pack\(fill=tk\.BOTH, expand=True\)\s*\n\s+)# Initial map draw', r'\1            # Initial map draw', content)
    content = re.sub(r'(\s+# Initial map draw\s*\n\s+)self\.draw_world_map', r'\1            self.draw_world_map', content)
    
    # Fix the else statement in for-else block in update_graphs
    content = re.sub(r'(\s+)else:', r'                    else:', content, count=1)
    
    # Fix the handle_export indentation
    content = re.sub(r'(\s+)def handle_export\(data_type\):', r'        def handle_export(data_type):', content)
    content = re.sub(r'(\s+)if data_type == "connections":', r'            if data_type == "connections":', content)
    content = re.sub(r'(\s+)elif data_type == "applications":', r'            elif data_type == "applications":', content)
    
    # Fix map_ax indentation
    content = re.sub(r'(\s+)self\.map_ax\.set_facecolor', r'                self.map_ax.set_facecolor', content)
    content = re.sub(r'(\s+)self\.map_canvas\.draw', r'                self.map_canvas.draw', content)
    
    # Fix monitor initialization
    content = re.sub(r'(\s+)self\.monitor = SystemNetworkMonitor', r'                self.monitor = SystemNetworkMonitor', content)
    
    # Fix monitor stop
    content = re.sub(r'(\s+)self\.monitor\.stop_capture', r'                    self.monitor.stop_capture', content)
    content = re.sub(r'(\s+)self\.traffic_anim\.event_source\.stop', r'                    self.traffic_anim.event_source.stop', content)
    
    # Fix collect_data method
    content = re.sub(r'(\s+)self\.packets_data\.append', r'                    self.packets_data.append', content)
    content = re.sub(r'(\s+)# Update protocol data', r'                    # Update protocol data', content)
    content = re.sub(r"(\s+)'total_packets': stats\['total_packets'\],", r"                        'total_packets': stats['total_packets'],", content)
    content = re.sub(r"(\s+)'total_bytes': stats\['total_bytes'\],", r"                        'total_bytes': stats['total_bytes'],", content)
    content = re.sub(r"(\s+)'packet_rate': packet_rate,", r"                        'packet_rate': packet_rate,", content)
    content = re.sub(r"(\s+)'byte_rate': byte_rate,", r"                        'byte_rate': byte_rate,", content)
    
    # Fix process queue
    content = re.sub(r'(\s+)# Process queue on main thread', r'                    # Process queue on main thread', content)
    content = re.sub(r'(\s+)self\.root\.after\(100, self\.process_queue\)', r'                    self.root.after(100, self.process_queue)', content)
    content = re.sub(r'(\s+)time\.sleep\(1\)', r'                    time.sleep(1)', content)
    content = re.sub(r'(\s+)except Exception as e:', r'                except Exception as e:', content)
    content = re.sub(r'(\s+)print\(f"Error updating data: \{e\}"\)', r'                    print(f"Error updating data: {e}")', content)
    
    # Fix geo data
    content = re.sub(r'(\s+)# Store geo data for map updates', r'                    # Store geo data for map updates', content)
    content = re.sub(r"(\s+)self\.geo_data = \{", r"                    self.geo_data = {", content)
    
    # Write the fixed content
    with open(output_file, 'w') as f:
        f.write(content)
    
    print(f"Fixed indentation in {output_file}")

if __name__ == "__main__":
    fix_indentation('WinIDS/netmon/network_analyzer_tkinter.py', 'WinIDS/netmon/network_analyzer_tkinter.py') 