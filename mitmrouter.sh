#!/bin/bash

# Detect network interfaces dynamically
WAN_IFACE=$(ip route | grep default | awk '{print $5}')
WIFI_IFACE=$(iwconfig 2>/dev/null | grep "IEEE 802.11" | awk '{print $1}' | head -n 1)
LAN_IFACE=$(ip -br link | grep -v "lo" | grep -v "$WAN_IFACE" | grep -v "$WIFI_IFACE" | awk '{print $1}' | head -n 1)

# VARIABLES
BR_IFACE="br0"
WIFI_SSID="engineer_debug"
WIFI_PASSWORD="mypassword"

LAN_IP="192.168.200.1"
LAN_SUBNET="24"  # Using CIDR notation instead of netmask
LAN_DHCP_START="192.168.200.10"
LAN_DHCP_END="192.168.200.100"
LAN_DNS_SERVER="1.1.1.1"

DNSMASQ_CONF="/tmp/dnsmasq.conf"
HOSTAPD_CONF="/tmp/hostapd.conf"

# Validate interface detection
if [ -z "$WAN_IFACE" ] || [ -z "$WIFI_IFACE" ] || [ -z "$LAN_IFACE" ]; then
    echo "Error: Could not detect network interfaces"
    echo "WAN: $WAN_IFACE, WIFI: $WIFI_IFACE, LAN: $LAN_IFACE"
    exit 1
fi

# Check for required arguments
if [ "$1" != "up" ] && [ "$1" != "down" ] || [ $# != 1 ]; then
    echo "Usage: $0 <up/down>"
    exit 1
fi

# Disable NetworkManager to prevent interference
sudo systemctl stop NetworkManager 2>/dev/null

# Stop existing services
sudo pkill -f wpa_supplicant
sudo pkill -f dnsmasq
sudo pkill -f hostapd

# Clean up existing bridge
sudo ip link del "$BR_IFACE" 2>/dev/null

if [ "$1" = "up" ]; then
    # Create dnsmasq configuration
    echo "interface=$BR_IFACE" > "$DNSMASQ_CONF"
    echo "dhcp-range=$LAN_DHCP_START,$LAN_DHCP_END,12h" >> "$DNSMASQ_CONF"
    echo "dhcp-option=6,$LAN_DNS_SERVER" >> "$DNSMASQ_CONF"

    # Create hostapd configuration
    cat > "$HOSTAPD_CONF" << EOF
interface=$WIFI_IFACE
bridge=$BR_IFACE
ssid=$WIFI_SSID
country_code=US
hw_mode=g
channel=11
wpa=2
wpa_passphrase=$WIFI_PASSWORD
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
ieee80211n=1
EOF

    # Bring up interfaces
    sudo ip link set dev "$WIFI_IFACE" up
    sudo ip link set dev "$WAN_IFACE" up
    sudo ip link set dev "$LAN_IFACE" up

    # Create bridge
    sudo ip link add name "$BR_IFACE" type bridge
    sudo ip link set "$LAN_IFACE" master "$BR_IFACE"
    sudo ip link set "$BR_IFACE" up

    # Configure IP
    sudo ip addr add "$LAN_IP"/"$LAN_SUBNET" dev "$BR_IFACE"

    # Setup NAT and forwarding
    sudo sysctl -w net.ipv4.ip_forward=1
    sudo iptables -t nat -F
    sudo iptables -F
    sudo iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE
    sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A FORWARD -i "$BR_IFACE" -o "$WAN_IFACE" -j ACCEPT

    # Start services
    sudo dnsmasq -C "$DNSMASQ_CONF"
    sudo hostapd "$HOSTAPD_CONF"
fi
