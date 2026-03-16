#!/bin/bash
#
# Docker entrypoint for UniFi OS Server.
# Handles directory initialization, UUID persistence, and system IP
# configuration before handing off to systemd (/sbin/init).

# --- UUID Persistence ---
if [ ! -f /data/uos_uuid ]; then
    if [ -n "${UOS_UUID+1}" ]; then
        echo "Setting UOS_UUID to $UOS_UUID"
        echo "$UOS_UUID" > /data/uos_uuid
    else
        echo "No UOS_UUID present, generating..."
        UUID=$(cat /proc/sys/kernel/random/uuid)
        # Spoof as a v5 UUID
        UOS_UUID=$(echo "$UUID" | sed s/./5/15)
        echo "Setting UOS_UUID to $UOS_UUID"
        echo "$UOS_UUID" > /data/uos_uuid
    fi
fi

# --- Version and Platform ---
echo "Setting UOS_SERVER_VERSION to $UOS_SERVER_VERSION"
echo "UOSSERVER.0000000.$UOS_SERVER_VERSION.0000000.000000.0000" > /usr/lib/version
echo "Setting FIRMWARE_PLATFORM to $FIRMWARE_PLATFORM"
echo "$FIRMWARE_PLATFORM" > /usr/lib/platform

# --- Network: eth0 alias to tap0 ---
if [ ! -d "/sys/devices/virtual/net/eth0" ] && [ -d "/sys/devices/virtual/net/tap0" ]; then
    ip link add name eth0 link tap0 type macvlan
    ip link set eth0 up
fi

# --- Log Directories ---
for dir_info in "/var/log/nginx:nginx:nginx" "/var/log/mongodb:mongodb:mongodb" "/var/log/rabbitmq:rabbitmq:rabbitmq"; do
    IFS=: read -r dir user group <<< "$dir_info"
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        chown "$user:$group" "$dir"
        chmod 755 "$dir"
    fi
done

# --- MongoDB lib directory ownership ---
if [ -d "/var/lib/mongodb" ]; then
    chown -R mongodb:mongodb /var/lib/mongodb
fi

# --- System IP Configuration ---
UNIFI_SYSTEM_PROPERTIES="/var/lib/unifi/system.properties"
if [ -n "${UOS_SYSTEM_IP+1}" ]; then
    echo "Setting UOS_SYSTEM_IP to $UOS_SYSTEM_IP"
    if [ ! -f "$UNIFI_SYSTEM_PROPERTIES" ]; then
        mkdir -p "$(dirname "$UNIFI_SYSTEM_PROPERTIES")"
        echo "system_ip=$UOS_SYSTEM_IP" >> "$UNIFI_SYSTEM_PROPERTIES"
    else
        if grep -q "^system_ip=.*" "$UNIFI_SYSTEM_PROPERTIES"; then
            sed -i 's/^system_ip=.*/system_ip='"$UOS_SYSTEM_IP"'/' "$UNIFI_SYSTEM_PROPERTIES"
        else
            echo "system_ip=$UOS_SYSTEM_IP" >> "$UNIFI_SYSTEM_PROPERTIES"
        fi
    fi
fi

# --- Start systemd ---
exec /sbin/init
