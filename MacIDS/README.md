# MacIDS - macOS Intrusion Detection System

MacIDS is a comprehensive network monitoring and intrusion detection system designed specifically for macOS. It provides real-time network traffic analysis, application identification, and visualization tools to help users monitor and secure their network connections.

## Features

- **Real-time Network Monitoring**: Capture and analyze network traffic on your macOS system in real-time
- **Application Identification**: Identify which applications are generating network traffic
- **Website Tracking**: Monitor and analyze websites and domains accessed from your system
- **Geolocation Visualization**: See where your network connections are going on a world map
- **Data Export**: Export connection data for further analysis

## Requirements

- macOS 10.14 or newer
- Python 3.7+
- Administrator privileges (for packet capture functionality)

## Installation

### Using pip

```bash
pip install MacIDS
```

### From source

```bash
git clone https://github.com/Nandhan-KA/MacIDS.git
cd MacIDS
pip install -e .
```

## Usage

### Network Monitor

To start the network monitoring tool:

```bash
sudo macids-netmon
```

Administrator privileges are required for capturing network packets.

You can also run it through Python:

```bash
sudo python -m macids.netmon
```

## How It Works

MacIDS uses Scapy to capture and analyze network packets at the system level. The application identifies processes associated with network connections, resolves domain names, and provides geographical information about connections.

Key components:
- Packet capture engine using Scapy
- Process-connection correlation
- Domain name resolution
- Geolocation services
- Interactive visualization using Matplotlib and Tkinter

## Key Differences from WinIDS

- Uses Scapy for packet capture instead of WinDivert
- Adapted for macOS network stack and process management
- Updated UI to match macOS design patterns
- Modified packet handling for macOS network architecture

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Original WinIDS project by Nandhan K
- MaxMind for GeoLite2 geolocation data
- Scapy project for packet manipulation tools
- Matplotlib for visualization components 