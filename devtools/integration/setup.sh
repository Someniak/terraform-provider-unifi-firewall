#!/usr/bin/env bash
#
# Bootstrap script for the UniFi OS Server integration test environment.
#
# This script:
#   1. Waits for UniFi OS Server to become ready
#   2. Detects if the setup wizard needs to be completed (first run)
#   3. Logs in via the UniFi OS auth API
#   4. Creates test networks
#   5. Outputs connection info
#
# Default credentials:
#   Admin:  admin / testpassword123
#   URL:    https://localhost:11443

set -euo pipefail
cd "$(dirname "$0")"

ADMIN_USER="admin"
ADMIN_PASS="testpassword123"
UNIFI_URL="https://localhost:11443"
COOKIE_FILE=$(mktemp)

cleanup() {
    rm -f "$COOKIE_FILE"
}
trap cleanup EXIT

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

log() {
    echo "[$(date '+%H:%M:%S')] $*"
}

wait_for_url() {
    local url="$1"
    local desc="$2"
    local max_attempts="${3:-90}"
    local attempt=0

    log "Waiting for $desc..."
    while [ $attempt -lt $max_attempts ]; do
        if curl -ks --max-time 5 "$url" > /dev/null 2>&1; then
            log "$desc is ready."
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 5
    done
    log "ERROR: $desc did not become ready after $((max_attempts * 5))s"
    return 1
}

api_call() {
    local method="$1"
    local endpoint="$2"
    local data="${3:-}"

    local args=(-ks -X "$method" -b "$COOKIE_FILE" -c "$COOKIE_FILE"
                -H "Content-Type: application/json")
    if [ -n "$data" ]; then
        args+=(-d "$data")
    fi

    curl "${args[@]}" "${UNIFI_URL}${endpoint}"
}

# --------------------------------------------------------------------------
# Step 1: Wait for UniFi OS Server
# --------------------------------------------------------------------------

log "=== UniFi OS Server Integration Setup ==="
log ""

wait_for_url "$UNIFI_URL" "UniFi OS Server" 90

# --------------------------------------------------------------------------
# Step 2: Check if setup wizard is needed
# --------------------------------------------------------------------------

log "Checking if setup wizard has been completed..."
LOGIN_RESULT=$(api_call POST "/api/auth/login" "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" 2>&1)

if echo "$LOGIN_RESULT" | grep -qE '"unique_id"|"userId"'; then
    log "Login successful — setup wizard already completed."
else
    log ""
    log "============================================================"
    log "  FIRST RUN: Complete the setup wizard"
    log "============================================================"
    log ""
    log "  1. Open $UNIFI_URL in your browser"
    log "     (accept the self-signed certificate warning)"
    log ""
    log "  2. Create a local admin account:"
    log "     Username: $ADMIN_USER"
    log "     Password: $ADMIN_PASS"
    log ""
    log "  3. Skip the Ubiquiti cloud sign-in (use offline mode)"
    log ""
    log "  4. After setup completes, re-run:"
    log "     make integration-up"
    log ""
    log "============================================================"
    exit 0
fi

# --------------------------------------------------------------------------
# Step 3: Create test networks
# --------------------------------------------------------------------------

log "Checking existing networks..."
NETWORKS=$(api_call GET "/proxy/network/api/s/default/rest/networkconf")

create_network() {
    local name="$1"
    local purpose="$2"
    local subnet="$3"
    local vlan="$4"

    if echo "$NETWORKS" | grep -q "\"name\":\"$name\""; then
        log "Network '$name' already exists, skipping."
        return
    fi

    log "Creating network: $name (VLAN $vlan, $subnet)..."
    api_call POST "/proxy/network/api/s/default/rest/networkconf" "{
        \"name\": \"$name\",
        \"purpose\": \"$purpose\",
        \"ip_subnet\": \"$subnet\",
        \"vlan\": $vlan,
        \"vlan_enabled\": true,
        \"dhcpd_enabled\": true,
        \"dhcpd_start\": \"$(echo "$subnet" | sed 's|0/24|100|')\",
        \"dhcpd_stop\": \"$(echo "$subnet" | sed 's|0/24|200|')\",
        \"enabled\": true
    }" > /dev/null
}

create_network "TestLAN"   "corporate" "192.168.10.0/24" 10
create_network "TestIoT"   "corporate" "192.168.20.0/24" 20
create_network "TestGuest" "guest"     "192.168.30.0/24" 30

# --------------------------------------------------------------------------
# Step 4: Output connection info
# --------------------------------------------------------------------------

log ""
log "=== Setup Complete ==="
log ""
log "UniFi OS Server:   $UNIFI_URL"
log "Admin credentials: $ADMIN_USER / $ADMIN_PASS"
log ""
log "To test, run:"
log ""
log "  make build"
log "  cd examples"
log "  export TF_CLI_CONFIG_FILE=dev_overrides.tfrc"
log "  terraform plan -var-file=integration.tfvars"
