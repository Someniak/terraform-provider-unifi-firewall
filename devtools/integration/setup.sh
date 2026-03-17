#!/usr/bin/env bash
#
# Bootstrap script for the UniFi OS Server integration test environment.
#
# This script:
#   1. Waits for UniFi OS Server to become ready
#   2. Detects if the setup wizard needs to be completed (first run)
#   3. Logs in via the UniFi OS auth API
#   4. Creates test networks
#   5. Hacks MongoDB to enable zone-based firewall (requires no physical gateway)
#   6. Creates an API key for integration testing
#   7. Outputs connection info
#
# Default credentials:
#   Admin:  admin / Testpassword123!
#   URL:    https://localhost:11443

set -euo pipefail
cd "$(dirname "$0")"

ADMIN_USER="admin"
ADMIN_PASS="Testpassword123!"
UNIFI_URL="https://localhost:11443"
COOKIE_FILE=$(mktemp)
CSRF_TOKEN=""

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

mongo_eval() {
    docker exec unifi-os-server mongo --port 27117 --quiet --eval "$1"
}

api_call() {
    local method="$1"
    local endpoint="$2"
    local data="${3:-}"

    local args=(-ks -X "$method" -b "$COOKIE_FILE" -c "$COOKIE_FILE"
                -H "Content-Type: application/json")
    if [ -n "$CSRF_TOKEN" ]; then
        args+=(-H "X-CSRF-Token: $CSRF_TOKEN")
    fi
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
# Step 2: Run setup wizard (if needed) and log in
# --------------------------------------------------------------------------

do_login() {
    local headers
    headers=$(mktemp)
    local payload
    payload=$(mktemp)
    cat > "$payload" <<LOGINEOF
{"username":"$ADMIN_USER","password":"$ADMIN_PASS"}
LOGINEOF
    LOGIN_RESULT=$(curl -ks -X POST -c "$COOKIE_FILE" -b "$COOKIE_FILE" -D "$headers" \
        -H "Content-Type: application/json" -d @"$payload" "${UNIFI_URL}/api/auth/login" 2>&1)
    CSRF_TOKEN=$(grep -i '^x-csrf-token:' "$headers" | tr -d '\r' | awk '{print $2}' || true)
    rm -f "$headers" "$payload"
}

log "Checking device state..."
SYSTEM_INFO=$(curl -ks "${UNIFI_URL}/api/system" 2>/dev/null)
IS_SETUP=$(echo "$SYSTEM_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('isSetup', False))" 2>/dev/null || echo "False")

DEVICE_STATE=$(echo "$SYSTEM_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('deviceState',''))" 2>/dev/null || true)

if [ "$IS_SETUP" = "False" ] && [ "$DEVICE_STATE" != "setup" ] && [ "$DEVICE_STATE" != "ready" ]; then
    log "First run detected — running setup wizard via API..."

    # Wait for deviceState to leave "notReady"
    for i in $(seq 1 60); do
        STATE=$(curl -ks "${UNIFI_URL}/api/system" 2>/dev/null | \
            python3 -c "import sys,json; print(json.load(sys.stdin).get('deviceState',''))" 2>/dev/null || true)
        if [ "$STATE" != "notReady" ] && [ -n "$STATE" ]; then
            log "  Device state: $STATE"
            break
        fi
        sleep 2
    done

    # Step 2a: Start setup session
    log "  Starting setup session..."
    SETUP_ID=$(curl -ks -X POST -H "Content-Type: application/json" \
        -d '{"sendTrace":true,"type":"webui"}' \
        "${UNIFI_URL}/api/setup/start" | \
        python3 -c "import sys,json; print(json.load(sys.stdin)['setupId'])" 2>/dev/null || true)

    if [ -z "$SETUP_ID" ]; then
        log "ERROR: Failed to start setup session."
        exit 1
    fi
    log "  Setup ID: $SETUP_ID"

    # Step 2b: Submit setup with local account (no UI cloud account)
    log "  Submitting setup configuration..."
    SETUP_PAYLOAD=$(mktemp)
    cat > "$SETUP_PAYLOAD" <<SETUPEOF
{"name":"UniFi Test Server","timezone":"UTC","optimizeNetwork":false,"sendDiagnostics":false,"newAccount":true,"advancedSetup":{"mode":"dhcp"},"username":"$ADMIN_USER","password":"$ADMIN_PASS","country":840,"setupId":"$SETUP_ID","raid":"raid5"}
SETUPEOF
    SETUP_RESULT=$(curl -ks -X POST -H "Content-Type: application/json" \
        -d @"$SETUP_PAYLOAD" "${UNIFI_URL}/api/setup" 2>&1)
    rm -f "$SETUP_PAYLOAD"
    log "  Setup submitted."

    # Wait for setup to complete (deviceState transitions from "notSetup" to "setup")
    log "  Waiting for setup to complete..."
    for i in $(seq 1 120); do
        STATE=$(curl -ks "${UNIFI_URL}/api/system" 2>/dev/null | \
            python3 -c "import sys,json; print(json.load(sys.stdin).get('deviceState',''))" 2>/dev/null || true)
        if [ "$STATE" = "setup" ] || [ "$STATE" = "ready" ]; then
            log "  Setup complete (state: $STATE)."
            break
        fi
        sleep 5
    done
fi

# Log in
log "Logging in..."
do_login

if echo "$LOGIN_RESULT" | grep -qE '"unique_id"|"userId"'; then
    log "Login successful."
    [ -n "$CSRF_TOKEN" ] && log "CSRF token acquired."
    USER_ID=$(echo "$LOGIN_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['unique_id'])" 2>/dev/null || true)
else
    log "ERROR: Login failed after setup. Result: $LOGIN_RESULT"
    exit 1
fi

# --------------------------------------------------------------------------
# Step 2c: Upgrade Network Application (if update available)
# --------------------------------------------------------------------------

# Get current Network Application version
CURRENT_NET_VERSION=$(curl -ks -b "$COOKIE_FILE" -H "X-CSRF-Token: $CSRF_TOKEN" \
    "${UNIFI_URL}/proxy/network/v2/api/info" 2>/dev/null | \
    python3 -c "import sys,json; print(json.load(sys.stdin).get('system',{}).get('version',''))" 2>/dev/null || true)
log "Current Network Application version: ${CURRENT_NET_VERSION:-unknown}"

# The zone-based firewall API requires Network Application >= 10.x.
# The UOS update mechanism requires WebSocket state that can't be driven from curl,
# so the user must trigger the upgrade manually via the browser.
NETWORK_MIN_VERSION="10"
NETWORK_MAJOR=$(echo "$CURRENT_NET_VERSION" | cut -d. -f1)

if [ -n "$NETWORK_MAJOR" ] && [ "$NETWORK_MAJOR" -lt "$NETWORK_MIN_VERSION" ] 2>/dev/null; then
    log ""
    log "============================================================"
    log "  ACTION REQUIRED: Upgrade Network Application"
    log "============================================================"
    log ""
    log "  Current version: $CURRENT_NET_VERSION (need >= $NETWORK_MIN_VERSION.x)"
    log ""
    log "  1. Open $UNIFI_URL/settings/updates in your browser"
    log "     (accept the self-signed certificate warning)"
    log "  2. Log in with: $ADMIN_USER / $ADMIN_PASS"
    log "  3. Click 'Update to ...' next to Network"
    log "  4. Click 'Proceed' and wait for the upgrade to complete"
    log "  5. Re-run: make integration-up"
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
    RESULT=$(api_call POST "/proxy/network/api/s/default/rest/networkconf" "{
        \"name\": \"$name\",
        \"purpose\": \"$purpose\",
        \"ip_subnet\": \"$subnet\",
        \"vlan\": $vlan,
        \"vlan_enabled\": true,
        \"dhcpd_enabled\": true,
        \"dhcpd_start\": \"$(echo "$subnet" | sed 's|1/24|100|')\",
        \"dhcpd_stop\": \"$(echo "$subnet" | sed 's|1/24|200|')\",
        \"enabled\": true
    }")
    if echo "$RESULT" | grep -q '"rc":"ok"'; then
        log "  -> Created successfully."
    else
        log "  -> WARNING: $RESULT"
    fi
}

create_network "TestLAN"   "corporate" "192.168.10.1/24" 10
create_network "TestIoT"   "corporate" "192.168.20.1/24" 20
create_network "TestGuest" "guest"     "192.168.30.1/24" 30

# --------------------------------------------------------------------------
# Step 4: Enable zone-based firewall via MongoDB hacks
# --------------------------------------------------------------------------
#
# The UniFi OS Server normally requires an adopted physical gateway (UDM, UXG,
# etc.) before zone-based firewall features become available. Since we have no
# real hardware, we inject the required records directly into MongoDB:
#
#   1. A fake UXG gateway device in the "device" collection
#   2. A site feature migration flag in "site_feature_migration"
#   3. Default firewall zones in "firewall_zone"
#
# The internal site_id comes from the "site" collection's "default" entry.

log "Enabling zone-based firewall via MongoDB..."

SITE_OID=$(mongo_eval '
    db = db.getSiblingDB("ace");
    var s = db.site.findOne({name: "default"});
    if (s) print(s._id.str); else print("");
')

if [ -z "$SITE_OID" ]; then
    log "WARNING: Could not find default site in MongoDB, skipping firewall hack."
else
    log "  Default site _id: $SITE_OID"

    # 4a. Insert fake UXG gateway device
    DEVICE_EXISTS=$(mongo_eval "
        db = db.getSiblingDB('ace');
        print(db.device.count({mac: 'fc:ec:da:00:00:01'}));
    ")
    if [ "$DEVICE_EXISTS" = "0" ]; then
        log "  Inserting fake UXG gateway device..."
        mongo_eval "
            db = db.getSiblingDB('ace');
            db.device.insertOne({
                ip: '192.168.1.1',
                mac: 'fc:ec:da:00:00:01',
                model: 'UXG',
                type: 'uxg',
                version: '4.0.6',
                adopted: true,
                state: 1,
                name: 'Fake Gateway Ultra',
                site_id: '$SITE_OID',
                inform_url: 'http://localhost:8080/inform',
                cfgversion: '0000000000000000',
                config_network: { type: 'dhcp', ip: '192.168.1.1' },
                board_rev: 21,
                required_version: '4.0.0',
                kernel_version: '5.10.0',
                hash_id: 'fake001',
                gateway_mac: 'fc:ec:da:00:00:01',
                fw_caps: 15,
                model_incompatible: false,
                model_in_eol: false,
                model_in_lts: false,
                internet: true,
                connected_at: Math.floor(Date.now()/1000),
                provisioned_at: Math.floor(Date.now()/1000),
                last_seen: Math.floor(Date.now()/1000),
                uptime: 86400,
                unsupported: false,
                unsupported_reason: 0
            });
        " > /dev/null
        log "  -> Fake gateway inserted."
    else
        log "  Fake gateway device already exists, skipping."
    fi

    # 4b. Insert site feature migration for ZONE_BASED_FIREWALL
    MIGRATION_EXISTS=$(mongo_eval "
        db = db.getSiblingDB('ace');
        print(db.site_feature_migration.count({site_id: '$SITE_OID', feature: 'ZONE_BASED_FIREWALL'}));
    ")
    if [ "$MIGRATION_EXISTS" = "0" ]; then
        log "  Inserting ZONE_BASED_FIREWALL site feature migration..."
        mongo_eval "
            db = db.getSiblingDB('ace');
            db.site_feature_migration.insertOne({
                site_id: '$SITE_OID',
                feature: 'ZONE_BASED_FIREWALL',
                timestamp: NumberLong(Date.now())
            });
        " > /dev/null
        log "  -> Feature migration inserted."
    else
        log "  ZONE_BASED_FIREWALL migration already exists, skipping."
    fi

    # 4c. Insert default firewall zones
    ZONE_COUNT=$(mongo_eval "
        db = db.getSiblingDB('ace');
        print(db.firewall_zone.count({site_id: '$SITE_OID'}));
    ")
    if [ "$ZONE_COUNT" = "0" ]; then
        log "  Inserting default firewall zones..."
        mongo_eval "
            db = db.getSiblingDB('ace');
            var zones = [
                {name:'Internal', zone_key:'internal', default_zone:true,  attr_no_edit:true, attr_no_delete:true, attr_hidden_id:'internal',
                 external_id:'$(python3 -c "import uuid; print(uuid.uuid4())")'},
                {name:'External', zone_key:'external', default_zone:true,  attr_no_edit:true, attr_no_delete:true, attr_hidden_id:'external',
                 external_id:'$(python3 -c "import uuid; print(uuid.uuid4())")'},
                {name:'Hotspot',  zone_key:'hotspot',  default_zone:true,  attr_no_edit:true, attr_no_delete:true, attr_hidden_id:'hotspot',
                 external_id:'$(python3 -c "import uuid; print(uuid.uuid4())")'},
                {name:'DMZ',      zone_key:'dmz',      default_zone:false, attr_no_edit:true, attr_no_delete:true, attr_hidden_id:'dmz',
                 external_id:'$(python3 -c "import uuid; print(uuid.uuid4())")'}
            ];
            zones.forEach(function(z) {
                z.site_id = '$SITE_OID';
                z.network_ids = [];
                db.firewall_zone.insertOne(z);
            });
        " > /dev/null
        log "  -> Default zones inserted (Internal, External, Hotspot, DMZ)."
    else
        log "  Firewall zones already exist ($ZONE_COUNT found), skipping."
    fi

    # 4d. Patch nginx to inject ZONE_BASED_FIREWALL feature flag for the UI
    #
    # The Java features service requires an active (connected) gateway to report
    # ZONE_BASED_FIREWALL as available. Since our fake device is never truly
    # connected, we patch nginx to:
    #   - Return {"feature_exists":true} for the feature-exists check
    #   - Serve a static described-features JSON with zone features appended
    #
    # The static approach avoids fragile sub_filter patterns — the described-
    # features response contains nested arrays with "}] that fool sub_filter.
    #
    NGINX_CONF="/data/unifi-core/config/http/shared-runnable-network.conf"
    FEATURES_JSON="/data/unifi-core/config/http/described-features.json"

    # Always regenerate the static described-features JSON (features can change
    # across container restarts / upgrades).  Fetch from the host side using the
    # session cookie we already have, then docker-cp the result into the container.
    log "  Generating static described-features JSON with zone features..."
    FEATURES_TMP=$(mktemp)
    api_call GET "/proxy/network/v2/api/site/default/described-features" | python3 -c "
import sys, json
data = json.load(sys.stdin)
# Strip any previously-injected zone features (idempotent)
data = [f for f in data if f.get('name') not in ('ZONE_BASED_FIREWALL', 'ZONE_BASED_FIREWALL_MIGRATION')]
# Clean up any zone features accidentally injected into limitations arrays
for f in data:
    if 'limitations' in f:
        f['limitations'] = [l for l in f['limitations'] if 'feature_exists' not in l]
data.append({'feature_exists': True, 'name': 'ZONE_BASED_FIREWALL'})
data.append({'feature_exists': True, 'name': 'ZONE_BASED_FIREWALL_MIGRATION'})
print(json.dumps(data, separators=(',', ':')))
" > "$FEATURES_TMP"
    if [ -s "$FEATURES_TMP" ]; then
        docker cp "$FEATURES_TMP" "unifi-os-server:$FEATURES_JSON"
        docker exec unifi-os-server chmod 644 "$FEATURES_JSON"
        log "  -> described-features.json generated."
    else
        log "  -> WARNING: Failed to generate described-features.json"
    fi
    rm -f "$FEATURES_TMP"

    # Copy nginx override config and reload
    log "  Patching nginx to inject ZONE_BASED_FIREWALL feature flag..."
    docker cp "$(dirname "$0")/nginx-network-override.conf" \
        "unifi-os-server:$NGINX_CONF"
    docker exec unifi-os-server nginx -t 2>/dev/null && \
        docker exec unifi-os-server nginx -s reload 2>/dev/null && \
        log "  -> Nginx patched and reloaded." || \
        log "  -> WARNING: Nginx patch failed."

    log "  Zone-based firewall enabled."
fi

# --------------------------------------------------------------------------
# Step 5: Create API key
# --------------------------------------------------------------------------

API_KEY_NAME="integration-test"

if [ -n "$USER_ID" ]; then
    EXISTING_KEYS=$(api_call GET "/proxy/users/api/v2/user/${USER_ID}/keys")

    if echo "$EXISTING_KEYS" | grep -q "\"name\":\"$API_KEY_NAME\""; then
        log "API key '$API_KEY_NAME' already exists, skipping."
        API_KEY="(already created — check previous run output)"
    else
        log "Creating API key: $API_KEY_NAME..."
        KEY_RESULT=$(api_call POST "/proxy/users/api/v2/user/${USER_ID}/keys" \
            "{\"name\":\"$API_KEY_NAME\"}")
        API_KEY=$(echo "$KEY_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['full_api_key'])" 2>/dev/null || true)
        if [ -n "$API_KEY" ]; then
            log "  -> API key created successfully."
            # Write API key into integration.tfvars
            SCRIPT_DIR="$(pwd)"
            EXAMPLES_DIR="$(cd "$SCRIPT_DIR/../../examples" && pwd)"
            TFVARS_FILE="$EXAMPLES_DIR/integration.tfvars"
            sed -i '' "s|unifi_api_key.*=.*|unifi_api_key  = \"$API_KEY\"|" "$TFVARS_FILE"
            log "  -> Updated $TFVARS_FILE with API key"
        else
            log "  -> WARNING: Failed to create API key: $KEY_RESULT"
        fi
    fi
else
    log "WARNING: Could not extract user ID, skipping API key creation."
    API_KEY=""
fi

# --------------------------------------------------------------------------
# Step 6: Create IoT zone and assign networks to zones via integration API
# --------------------------------------------------------------------------
#
# The integration API requires API key auth (not cookie auth). We read the
# key from integration.tfvars which was written in step 5.

SCRIPT_DIR="$(pwd)"
TFVARS_FILE="$(cd "$SCRIPT_DIR/../../examples" && pwd)/integration.tfvars"
SAVED_API_KEY=$(grep 'unifi_api_key' "$TFVARS_FILE" 2>/dev/null | sed 's/.*= *"\(.*\)"/\1/' || true)

if [ -z "$SAVED_API_KEY" ]; then
    log "WARNING: No API key found in integration.tfvars, skipping zone/network setup."
else
    int_api_call() {
        local method="$1"
        local endpoint="$2"
        local data="${3:-}"

        local args=(-ks -X "$method"
                    -H "X-API-Key: $SAVED_API_KEY"
                    -H "Content-Type: application/json")
        if [ -n "$data" ]; then
            args+=(-d "$data")
        fi
        curl "${args[@]}" "${UNIFI_URL}${endpoint}"
    }

    # Discover the API site UUID
    SITE_UUID=$(int_api_call GET "/proxy/network/integration/v1/sites?limit=200" | \
        python3 -c "import sys,json; print(json.load(sys.stdin)['data'][0]['id'])" 2>/dev/null || true)

    if [ -z "$SITE_UUID" ]; then
        log "WARNING: Could not discover site UUID from integration API."
    else
        log "Site UUID: $SITE_UUID"
        API_BASE="/proxy/network/integration/v1/sites/$SITE_UUID"

        # Create IoT zone if it doesn't exist
        ZONES_JSON=$(int_api_call GET "$API_BASE/firewall/zones?limit=200")
        if echo "$ZONES_JSON" | grep -q '"name":"IoT"'; then
            log "IoT zone already exists, skipping."
        else
            log "Creating IoT zone via API..."
            IOT_RESULT=$(int_api_call POST "$API_BASE/firewall/zones" '{"name":"IoT","networkIds":[]}')
            if echo "$IOT_RESULT" | grep -q '"id"'; then
                log "  -> IoT zone created."
                ZONES_JSON=$(int_api_call GET "$API_BASE/firewall/zones?limit=200")
            else
                log "  -> WARNING: Failed to create IoT zone: $IOT_RESULT"
            fi
        fi

        # Discover network and zone IDs
        NETWORKS_JSON=$(int_api_call GET "$API_BASE/networks?limit=200")

        get_id_by_name() {
            local json="$1" name="$2"
            echo "$json" | python3 -c "
import sys, json
for item in json.load(sys.stdin)['data']:
    if item['name'] == '$name':
        print(item['id'])
        break
" 2>/dev/null || true
        }

        TESTLAN_NET_ID=$(get_id_by_name "$NETWORKS_JSON" "TestLAN")
        TESTIOT_NET_ID=$(get_id_by_name "$NETWORKS_JSON" "TestIoT")
        TESTGUEST_NET_ID=$(get_id_by_name "$NETWORKS_JSON" "TestGuest")

        INTERNAL_ZONE_ID=$(get_id_by_name "$ZONES_JSON" "Internal")
        IOT_ZONE_ID=$(get_id_by_name "$ZONES_JSON" "IoT")
        HOTSPOT_ZONE_ID=$(get_id_by_name "$ZONES_JSON" "Hotspot")

        # Assign networks to zones
        assign_network_to_zone() {
            local zone_name="$1" zone_id="$2" net_id="$3"
            if [ -n "$zone_id" ] && [ -n "$net_id" ]; then
                log "Assigning network -> $zone_name..."
                int_api_call PUT "$API_BASE/firewall/zones/$zone_id" \
                    "{\"networkIds\":[\"$net_id\"]}" > /dev/null
            fi
        }

        assign_network_to_zone "Internal" "$INTERNAL_ZONE_ID" "$TESTLAN_NET_ID"
        assign_network_to_zone "IoT"      "$IOT_ZONE_ID"      "$TESTIOT_NET_ID"
        assign_network_to_zone "Hotspot"  "$HOTSPOT_ZONE_ID"  "$TESTGUEST_NET_ID"
        log "  -> Network-to-zone assignments complete."

        # Write IoT network ID into integration.tfvars
        if [ -n "$TESTIOT_NET_ID" ]; then
            if grep -q 'iot_network_id' "$TFVARS_FILE" 2>/dev/null; then
                sed -i '' "s|iot_network_id.*=.*|iot_network_id  = \"$TESTIOT_NET_ID\"|" "$TFVARS_FILE"
            else
                echo "iot_network_id  = \"$TESTIOT_NET_ID\"" >> "$TFVARS_FILE"
            fi
            log "  -> Wrote iot_network_id=$TESTIOT_NET_ID to integration.tfvars"
        fi
    fi
fi

# --------------------------------------------------------------------------
# Step 7: Insert fake client device for fixedip testing
# --------------------------------------------------------------------------
#
# The fixedip resource requires a known client device. We insert a fake one
# into MongoDB so the REST API (/api/s/default/rest/user) can find it.

if [ -n "$SITE_OID" ]; then
    FAKE_MAC="00:11:22:33:44:55"
    FAKE_CLIENT_EXISTS=$(mongo_eval "
        db = db.getSiblingDB('ace');
        print(db.user.count({mac: '$FAKE_MAC', site_id: '$SITE_OID'}));
    ")
    if [ "$FAKE_CLIENT_EXISTS" = "0" ]; then
        # Look up the TestLAN network _id from MongoDB
        TESTLAN_OID=$(mongo_eval "
            db = db.getSiblingDB('ace');
            var n = db.networkconf.findOne({name: 'TestLAN', site_id: '$SITE_OID'});
            if (n) print(n._id.str); else print('');
        ")
        log "Inserting fake client device (MAC: $FAKE_MAC)..."
        mongo_eval "
            db = db.getSiblingDB('ace');
            db.user.insertOne({
                mac: '$FAKE_MAC',
                site_id: '$SITE_OID',
                name: 'Fake Test Server',
                hostname: 'fake-server',
                use_fixedip: false,
                network_id: '$TESTLAN_OID',
                fixed_ip: '',
                noted: true,
                usergroup_id: '',
                last_seen: Math.floor(Date.now()/1000),
                first_seen: Math.floor(Date.now()/1000),
                oui: 'Fake',
                is_wired: true
            });
        " > /dev/null
        log "  -> Fake client inserted."
    else
        log "Fake client device already exists, skipping."
    fi
fi

# --------------------------------------------------------------------------
# Step 8: Output connection info
# --------------------------------------------------------------------------

log ""
log "=== Setup Complete ==="
log ""
log "UniFi OS Server:   $UNIFI_URL"
log "Admin credentials: $ADMIN_USER / $ADMIN_PASS"
if [ -n "$API_KEY" ]; then
    log "API Key:           $API_KEY"
fi
log ""
log "To test, run:"
log ""
log "  make build"
log "  cd examples"
log "  export TF_CLI_CONFIG_FILE=dev_overrides.tfrc"
log "  terraform plan -var-file=integration.tfvars"
