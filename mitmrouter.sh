#!/usr/bin/env bash
set -euo pipefail

BR_IFACE="${BR_IFACE:-br0}"
WIFI_SSID="${WIFI_SSID:-engineer_debug}"
WIFI_PASSWORD="${WIFI_PASSWORD:-mypassword}"

LAN_IP="${LAN_IP:-192.168.200.1}"
LAN_SUBNET="${LAN_SUBNET:-24}" # Using CIDR notation instead of netmask
LAN_DHCP_START="${LAN_DHCP_START:-192.168.200.10}"
LAN_DHCP_END="${LAN_DHCP_END:-192.168.200.100}"
LAN_DNS_SERVER="${LAN_DNS_SERVER:-1.1.1.1}"

DNSMASQ_CONF="${DNSMASQ_CONF:-/tmp/mitmrouter-dnsmasq.conf}"
HOSTAPD_CONF="${HOSTAPD_CONF:-/tmp/mitmrouter-hostapd.conf}"
DNSMASQ_PID_FILE="${DNSMASQ_PID_FILE:-/tmp/mitmrouter-dnsmasq.pid}"
STATE_FILE="${STATE_FILE:-/tmp/mitmrouter.state}"
RULE_COMMENT="mitmrouter"

log() {
    printf '[mitmrouter] %s\n' "$*"
}

die() {
    printf '[mitmrouter] ERROR: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: mitmrouter.sh <up|down>

Environment overrides:
  WAN_IFACE, WIFI_IFACE, LAN_IFACE - manually set interface names
  BR_IFACE, WIFI_SSID, WIFI_PASSWORD
  LAN_IP, LAN_SUBNET, LAN_DHCP_START, LAN_DHCP_END, LAN_DNS_SERVER
  DNSMASQ_CONF, HOSTAPD_CONF, DNSMASQ_PID_FILE, STATE_FILE
EOF
    exit 1
}

require_root() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        die "Run as root (e.g., sudo $0 up)"
    fi
}

require_commands() {
    local missing=()
    for cmd in ip iptables sysctl dnsmasq hostapd awk grep; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done

    if [ "${#missing[@]}" -gt 0 ]; then
        die "Missing required commands: ${missing[*]}"
    fi
}

discover_wan_iface() {
    ip route | awk '$1 == "default" {print $5; exit}'
}

discover_wifi_iface() {
    if command -v iw >/dev/null 2>&1; then
        iw dev 2>/dev/null | awk '$1 == "Interface" {print $2; exit}'
    fi

    if command -v iwconfig >/dev/null 2>&1; then
        iwconfig 2>/dev/null | awk '/IEEE 802.11/ {print $1; exit}'
    fi
}

discover_lan_iface() {
    ip -br link |
        awk -v wan="$WAN_IFACE" -v wifi="$WIFI_IFACE" '$1 != "lo" && $1 != wan && $1 != wifi {print $1; exit}'
}

assert_interfaces() {
    WAN_IFACE="${WAN_IFACE:-$(discover_wan_iface)}"
    WIFI_IFACE="${WIFI_IFACE:-$(discover_wifi_iface)}"
    LAN_IFACE="${LAN_IFACE:-$(discover_lan_iface)}"

    if [ -z "${WAN_IFACE:-}" ] || [ -z "${WIFI_IFACE:-}" ] || [ -z "${LAN_IFACE:-}" ]; then
        die "Could not detect interfaces (WAN: ${WAN_IFACE:-?}, WIFI: ${WIFI_IFACE:-?}, LAN: ${LAN_IFACE:-?}). Provide overrides via environment variables."
    fi

    if [ "$WAN_IFACE" = "$LAN_IFACE" ] || [ "$WAN_IFACE" = "$WIFI_IFACE" ] || [ "$LAN_IFACE" = "$WIFI_IFACE" ]; then
        die "Interface detection produced duplicates. Set WAN_IFACE, WIFI_IFACE, and LAN_IFACE explicitly."
    fi
}

ensure_iptables_rule() {
    local table=$1 chain=$2; shift 2
    if ! iptables -t "$table" -C "$chain" "$@" >/dev/null 2>&1; then
        iptables -t "$table" -A "$chain" "$@"
    fi
}

remove_iptables_rule() {
    local table=$1 chain=$2; shift 2
    if iptables -t "$table" -C "$chain" "$@" >/dev/null 2>&1; then
        iptables -t "$table" -D "$chain" "$@"
    fi
}

write_dnsmasq_conf() {
    cat >"$DNSMASQ_CONF" <<EOF
interface=$BR_IFACE
bind-interfaces
dhcp-range=$LAN_DHCP_START,$LAN_DHCP_END,12h
dhcp-option=6,$LAN_DNS_SERVER
EOF
}

write_hostapd_conf() {
    cat >"$HOSTAPD_CONF" <<EOF
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
}

record_state() {
    umask 077
    cat >"$STATE_FILE" <<EOF
NETWORK_MANAGER_WAS_ACTIVE=$NETWORK_MANAGER_WAS_ACTIVE
PREV_IP_FORWARD=$PREV_IP_FORWARD
WAN_IFACE=$WAN_IFACE
LAN_IFACE=$LAN_IFACE
WIFI_IFACE=$WIFI_IFACE
BR_IFACE=$BR_IFACE
DNSMASQ_CONF=$DNSMASQ_CONF
HOSTAPD_CONF=$HOSTAPD_CONF
DNSMASQ_PID_FILE=$DNSMASQ_PID_FILE
EOF
}

restore_state() {
    if [ ! -f "$STATE_FILE" ]; then
        die "No state file found. Was 'up' run first?"
    fi

    # shellcheck disable=SC1090
    . "$STATE_FILE"
}

stop_network_manager() {
    NETWORK_MANAGER_WAS_ACTIVE=0
    if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files NetworkManager.service >/dev/null 2>&1; then
        if systemctl is-active --quiet NetworkManager; then
            NETWORK_MANAGER_WAS_ACTIVE=1
            systemctl stop NetworkManager
        fi
    fi
}

maybe_restart_network_manager() {
    if [ "${NETWORK_MANAGER_WAS_ACTIVE:-0}" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
        systemctl start NetworkManager || log "NetworkManager could not be restarted automatically"
    fi
}

bring_up() {
    assert_interfaces
    stop_network_manager

    log "Using WAN=$WAN_IFACE WIFI=$WIFI_IFACE LAN=$LAN_IFACE BRIDGE=$BR_IFACE"

    PREV_IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)

    write_dnsmasq_conf
    write_hostapd_conf

    ip link set dev "$WIFI_IFACE" down || true
    ip link set dev "$LAN_IFACE" down || true
    ip link set dev "$BR_IFACE" down 2>/dev/null || true
    ip link del "$BR_IFACE" 2>/dev/null || true

    ip link add name "$BR_IFACE" type bridge
    ip link set "$LAN_IFACE" master "$BR_IFACE"
    ip link set "$WIFI_IFACE" master "$BR_IFACE"

    ip link set dev "$WIFI_IFACE" up
    ip link set dev "$WAN_IFACE" up
    ip link set dev "$LAN_IFACE" up
    ip link set "$BR_IFACE" up

    ip addr add "$LAN_IP/$LAN_SUBNET" dev "$BR_IFACE"

    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    ensure_iptables_rule nat POSTROUTING -o "$WAN_IFACE" -m comment --comment "$RULE_COMMENT" -j MASQUERADE
    ensure_iptables_rule filter FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$RULE_COMMENT" -j ACCEPT
    ensure_iptables_rule filter FORWARD -i "$BR_IFACE" -o "$WAN_IFACE" -m comment --comment "$RULE_COMMENT" -j ACCEPT

    dnsmasq --conf-file="$DNSMASQ_CONF" --interface="$BR_IFACE" --no-hosts --keep-in-foreground --pid-file="$DNSMASQ_PID_FILE" &
    DNSMASQ_PID=$!
    sleep 1
    if ! kill -0 "$DNSMASQ_PID" >/dev/null 2>&1; then
        wait "$DNSMASQ_PID" || true
        die "dnsmasq failed to start; check $DNSMASQ_CONF"
    fi

    hostapd -B "$HOSTAPD_CONF"

    record_state

    log "Router is up. dnsmasq PID $DNSMASQ_PID, hostapd config $HOSTAPD_CONF"
}

bring_down() {
    restore_state

    log "Stopping services"
    if [ -f "$DNSMASQ_PID_FILE" ]; then
        kill "$(cat "$DNSMASQ_PID_FILE")" >/dev/null 2>&1 || true
    fi
    pkill -f "$DNSMASQ_CONF" >/dev/null 2>&1 || true
    pkill -f "$HOSTAPD_CONF" >/dev/null 2>&1 || true

    log "Removing iptables rules"
    remove_iptables_rule nat POSTROUTING -o "$WAN_IFACE" -m comment --comment "$RULE_COMMENT" -j MASQUERADE
    remove_iptables_rule filter FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$RULE_COMMENT" -j ACCEPT
    remove_iptables_rule filter FORWARD -i "$BR_IFACE" -o "$WAN_IFACE" -m comment --comment "$RULE_COMMENT" -j ACCEPT

    log "Restoring IP forwarding to $PREV_IP_FORWARD"
    sysctl -w net.ipv4.ip_forward="$PREV_IP_FORWARD" >/dev/null

    ip addr flush dev "$BR_IFACE" >/dev/null 2>&1 || true
    ip link set "$LAN_IFACE" nomaster >/dev/null 2>&1 || true
    ip link set "$WIFI_IFACE" nomaster >/dev/null 2>&1 || true
    ip link set "$BR_IFACE" down >/dev/null 2>&1 || true
    ip link del "$BR_IFACE" >/dev/null 2>&1 || true

    rm -f "$DNSMASQ_CONF" "$HOSTAPD_CONF" "$DNSMASQ_PID_FILE" "$STATE_FILE"

    maybe_restart_network_manager

    log "Router is down and cleaned up"
}

main() {
    if [ $# -ne 1 ]; then
        usage
    fi

    require_root
    require_commands

    case "$1" in
        up) bring_up ;;
        down) bring_down ;;
        *) usage ;;
    esac
}

main "$@"
