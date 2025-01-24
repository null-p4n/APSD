# APSD - ex / mitmrouter
Bash script to automate setup of Linux router useful for IoT device traffic analysis and SSL mitm

![Arch](./img/arch.jpg)

# Access Point Secure Debugging

## Overview

This Bash script automates the process of creating a wireless router/access point on a Linux system (specifically tested on Kali 2024.04). It allows you to quickly set up a network bridge with NAT, DHCP, and WiFi access point functionality.

## Features

- Dynamically detect network interfaces
- Create a bridge between LAN and WiFi interfaces
- Set up NAT (Network Address Translation)
- Configure DHCP server
- Create a secure WiFi access point
- Easy up/down management

## Prerequisites

- Kali Linux 2024.04 (or similar Debian-based distribution)
- Wireless adapter supporting AP mode
- Root/sudo access

### Required Packages

```bash
sudo apt update
sudo apt install -y hostapd dnsmasq iptables net-tools wireless-tools
```

## Configuration

Modify the following variables in the script to match your network setup:

- `WIFI_SSID`: Name of the WiFi network
- `WIFI_PASSWORD`: WiFi network password
- `LAN_IP`: IP address for the bridge interface
- `LAN_SUBNET`: Subnet in CIDR notation (e.g., 24 for 255.255.255.0)
- `LAN_DHCP_START` and `LAN_DHCP_END`: DHCP address range
- `LAN_DNS_SERVER`: DNS server to use

## Usage

```bash
# Make the script executable
chmod +x mitmrouter.sh

# Bring up the wireless router
sudo ./mitmrouter.sh up

# Tear down the wireless router
sudo ./mitmrouter.sh down
```

## Troubleshooting

1. Verify interface names using `ip link` or `iwconfig`
2. Ensure wireless adapter supports AP mode
3. Check that no other network management tools are interfering

## Limitations

- Requires manual interface configuration
- Temporarily disables NetworkManager
- Assumes a single wireless and LAN interface

## Security Considerations

- Change default passwords
- Use strong WiFi encryption
- Limit DHCP address range
- Consider additional firewall rules

## Contributing

Pull requests and improvements are welcome!

```
./mitmrouter.sh: <up/down>
```

The `./mitmrouter.sh up` command will bring down all the linux router components and then build them back up again

The `./mitmrouter.sh down` command will bring down all the linux router components


