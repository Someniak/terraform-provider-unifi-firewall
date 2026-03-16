#!/usr/bin/env python3
"""
Mock UniFi Network API server with a live web dashboard.

Run:
    pip install flask
    python server.py

Then:
    - API listens on http://localhost:5100
    - Dashboard at  http://localhost:5100/ui
    - Point your Terraform provider at this URL with any API key

The dashboard auto-refreshes via Server-Sent Events so you can watch
resources change in realtime as terraform plan/apply runs.
"""

import json
import queue
import threading
import time
import uuid
from datetime import datetime

from flask import Flask, Response, jsonify, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# In-memory data store
# ---------------------------------------------------------------------------

lock = threading.RLock()

sites = [
    {"id": "site-default", "name": "Default", "internalReference": "default"},
]

# All keyed by site_id
zones: dict[str, list[dict]] = {
    "site-default": [
        {"id": "zone-lan", "name": "Internal", "networkIds": ["net-1"]},
        {"id": "zone-wan", "name": "External", "networkIds": ["net-2"]},
        {"id": "zone-guest", "name": "Hotspot", "networkIds": ["net-3"]},
        {"id": "zone-iot", "name": "IoT", "networkIds": ["net-4"]},
    ],
}

networks: dict[str, list[dict]] = {
    "site-default": [
        {"id": "net-1", "name": "Default", "vlanId": 1, "management": "GATEWAY"},
        {"id": "net-2", "name": "WAN", "vlanId": 0, "management": "GATEWAY"},
        {"id": "net-3", "name": "Guest", "vlanId": 100, "management": "GATEWAY"},
        {"id": "net-4", "name": "IoT", "vlanId": 200, "management": "GATEWAY"},
    ],
}

fw_policies: dict[str, list[dict]] = {"site-default": []}
dns_policies: dict[str, list[dict]] = {"site-default": []}

# ---------------------------------------------------------------------------
# Event log + SSE for live dashboard
# ---------------------------------------------------------------------------

event_log: list[dict] = []
sse_subscribers: list[queue.Queue] = []


def log_event(action: str, resource_type: str, resource_id: str, detail: str = ""):
    entry = {
        "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "detail": detail,
    }
    event_log.append(entry)
    # Keep last 200 events
    if len(event_log) > 200:
        event_log.pop(0)
    broadcast_update()


def broadcast_update():
    """Push a snapshot to all SSE listeners."""
    snapshot = build_snapshot()
    data = json.dumps(snapshot)
    dead = []
    for q in sse_subscribers:
        try:
            q.put_nowait(data)
        except queue.Full:
            dead.append(q)
    for q in dead:
        sse_subscribers.remove(q)


def build_snapshot() -> dict:
    with lock:
        return {
            "sites": sites,
            "zones": {k: v[:] for k, v in zones.items()},
            "networks": {k: v[:] for k, v in networks.items()},
            "fw_policies": {k: v[:] for k, v in fw_policies.items()},
            "dns_policies": {k: v[:] for k, v in dns_policies.items()},
            "events": event_log[-50:],
            "stats": {
                "total_fw_policies": sum(len(v) for v in fw_policies.values()),
                "total_dns_policies": sum(len(v) for v in dns_policies.values()),
                "total_zones": sum(len(v) for v in zones.values()),
                "total_networks": sum(len(v) for v in networks.values()),
            },
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_list_response(items):
    """Build a paginated list response matching the real UniFi API envelope."""
    offset = request.args.get("offset", 0, type=int)
    limit = request.args.get("limit", 25, type=int)
    page = items[offset : offset + limit]
    return jsonify(
        {
            "offset": offset,
            "limit": limit,
            "count": len(page),
            "totalCount": len(items),
            "data": page,
        }
    )


def error_response(status, code, message, details=None):
    """Return a structured error response matching real API patterns."""
    body = {"error": code, "message": message}
    if details:
        body["details"] = details
    log_event("ERROR", code, str(status), message)
    return jsonify(body), status


def _get_nested(data, dotpath):
    """Traverse a dict by dot-separated keys (e.g. 'action.type')."""
    obj = data
    for key in dotpath.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def validate_required_fields(data, required_fields, enum_rules):
    """Check required keys and enum values. Returns list of error strings."""
    errors = []
    for field in required_fields:
        if _get_nested(data, field) is None:
            errors.append(f"missing required field: '{field}'")
    for dotpath, allowed in enum_rules.items():
        val = _get_nested(data, dotpath)
        if val is not None and val not in allowed:
            errors.append(f"invalid value for '{dotpath}': '{val}' (must be one of {allowed})")
    return errors


FW_POLICY_REQUIRED = ["name", "action", "source", "destination", "ipProtocolScope"]
FW_POLICY_ENUMS = {
    "action.type": ["ALLOW", "BLOCK", "REJECT"],
    "ipProtocolScope.ipVersion": ["IPV4", "IPV6", "IPV4_AND_IPV6"],
}

DNS_POLICY_REQUIRED = ["type", "domain"]
DNS_POLICY_ENUMS = {
    "type": [
        "A_RECORD",
        "AAAA_RECORD",
        "CNAME_RECORD",
        "MX_RECORD",
        "TXT_RECORD",
        "SRV_RECORD",
        "FORWARD_DOMAIN",
    ],
}


def validate_zone_refs(site_id, data):
    """Check that source/destination zoneIds reference existing zones."""
    errors = []
    known_ids = {z["id"] for z in zones.get(site_id, [])}
    for field in ("source", "destination"):
        obj = data.get(field, {})
        zone_id = obj.get("zoneId")
        if zone_id and zone_id not in known_ids:
            errors.append(f"{field}.zoneId '{zone_id}' not found in site '{site_id}'")
    return errors


# ---------------------------------------------------------------------------
# API key check (accepts anything, just logs it)
# ---------------------------------------------------------------------------


@app.before_request
def check_api_key():
    # Skip for UI routes
    if request.path.startswith("/ui") or request.path.startswith("/sse"):
        return
    api_key = request.headers.get("X-API-Key", "")
    if not api_key:
        return error_response(401, "unauthorized", "Missing X-API-Key header")


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

# Sites
@app.route("/v1/sites", methods=["GET"])
def list_sites():
    log_event("LIST", "site", "*")
    return make_list_response(sites)


# Firewall Zones
@app.route("/v1/sites/<site_id>/firewall/zones", methods=["GET"])
def list_zones(site_id):
    log_event("LIST", "zone", "*", f"site={site_id}")
    with lock:
        items = zones.get(site_id, [])
        return make_list_response(items)


@app.route("/v1/sites/<site_id>/firewall/zones", methods=["POST"])
def create_zone(site_id):
    data = request.get_json()
    data["id"] = f"zone-{uuid.uuid4().hex[:8]}"
    with lock:
        zones.setdefault(site_id, []).append(data)
    log_event("CREATE", "zone", data["id"], data.get("name", ""))
    return jsonify(data), 201


# Networks
@app.route("/v1/sites/<site_id>/networks", methods=["GET"])
def list_networks(site_id):
    log_event("LIST", "network", "*", f"site={site_id}")
    with lock:
        items = networks.get(site_id, [])
        return make_list_response(items)


# Firewall Policies
@app.route("/v1/sites/<site_id>/firewall/policies", methods=["GET"])
def list_fw_policies(site_id):
    log_event("LIST", "fw_policy", "*", f"site={site_id}")
    with lock:
        items = fw_policies.get(site_id, [])
        return make_list_response(items)


@app.route("/v1/sites/<site_id>/firewall/policies", methods=["POST"])
def create_fw_policy(site_id):
    data = request.get_json()
    errors = validate_required_fields(data, FW_POLICY_REQUIRED, FW_POLICY_ENUMS)
    errors.extend(validate_zone_refs(site_id, data))
    if errors:
        return error_response(422, "validation_failed", "Invalid firewall policy", details=errors)
    data["id"] = f"fw-{uuid.uuid4().hex[:8]}"
    with lock:
        fw_policies.setdefault(site_id, []).append(data)
    log_event("CREATE", "fw_policy", data["id"], data.get("name", ""))
    return jsonify(data), 201


@app.route("/v1/sites/<site_id>/firewall/policies/<policy_id>", methods=["GET"])
def get_fw_policy(site_id, policy_id):
    log_event("READ", "fw_policy", policy_id)
    with lock:
        for p in fw_policies.get(site_id, []):
            if p["id"] == policy_id:
                return jsonify(p)
    return error_response(404, "not_found", f"Firewall policy '{policy_id}' not found")


@app.route("/v1/sites/<site_id>/firewall/policies/<policy_id>", methods=["PUT"])
def update_fw_policy(site_id, policy_id):
    data = request.get_json()
    errors = validate_required_fields(data, FW_POLICY_REQUIRED, FW_POLICY_ENUMS)
    errors.extend(validate_zone_refs(site_id, data))
    if errors:
        return error_response(422, "validation_failed", "Invalid firewall policy", details=errors)
    data["id"] = policy_id
    with lock:
        policies = fw_policies.get(site_id, [])
        for i, p in enumerate(policies):
            if p["id"] == policy_id:
                policies[i] = data
                log_event("UPDATE", "fw_policy", policy_id, data.get("name", ""))
                return jsonify(data)
    return error_response(404, "not_found", f"Firewall policy '{policy_id}' not found")


@app.route("/v1/sites/<site_id>/firewall/policies/<policy_id>", methods=["DELETE"])
def delete_fw_policy(site_id, policy_id):
    with lock:
        policies = fw_policies.get(site_id, [])
        for i, p in enumerate(policies):
            if p["id"] == policy_id:
                policies.pop(i)
                log_event("DELETE", "fw_policy", policy_id)
                return "", 204
    return error_response(404, "not_found", f"Firewall policy '{policy_id}' not found")


@app.route("/v1/sites/<site_id>/firewall/policies/<policy_id>", methods=["PATCH"])
def patch_fw_policy(site_id, policy_id):
    patch = request.get_json()
    with lock:
        policies = fw_policies.get(site_id, [])
        for i, p in enumerate(policies):
            if p["id"] == policy_id:
                p.update(patch)
                p["id"] = policy_id
                log_event("PATCH", "fw_policy", policy_id)
                return jsonify(p)
    return error_response(404, "not_found", f"Firewall policy '{policy_id}' not found")


# DNS Policies
@app.route("/v1/sites/<site_id>/dns/policies", methods=["GET"])
def list_dns_policies(site_id):
    log_event("LIST", "dns_policy", "*", f"site={site_id}")
    with lock:
        items = dns_policies.get(site_id, [])
        return make_list_response(items)


@app.route("/v1/sites/<site_id>/dns/policies", methods=["POST"])
def create_dns_policy(site_id):
    data = request.get_json()
    errors = validate_required_fields(data, DNS_POLICY_REQUIRED, DNS_POLICY_ENUMS)
    if errors:
        return error_response(422, "validation_failed", "Invalid DNS policy", details=errors)
    data["id"] = f"dns-{uuid.uuid4().hex[:8]}"
    with lock:
        dns_policies.setdefault(site_id, []).append(data)
    log_event("CREATE", "dns_policy", data["id"], data.get("domain", ""))
    return jsonify(data), 201


@app.route("/v1/sites/<site_id>/dns/policies/<policy_id>", methods=["GET"])
def get_dns_policy(site_id, policy_id):
    log_event("READ", "dns_policy", policy_id)
    with lock:
        for p in dns_policies.get(site_id, []):
            if p["id"] == policy_id:
                return jsonify(p)
    return error_response(404, "not_found", f"DNS policy '{policy_id}' not found")


@app.route("/v1/sites/<site_id>/dns/policies/<policy_id>", methods=["PUT"])
def update_dns_policy(site_id, policy_id):
    data = request.get_json()
    errors = validate_required_fields(data, DNS_POLICY_REQUIRED, DNS_POLICY_ENUMS)
    if errors:
        return error_response(422, "validation_failed", "Invalid DNS policy", details=errors)
    data["id"] = policy_id
    with lock:
        policies = dns_policies.get(site_id, [])
        for i, p in enumerate(policies):
            if p["id"] == policy_id:
                policies[i] = data
                log_event("UPDATE", "dns_policy", policy_id, data.get("domain", ""))
                return jsonify(data)
    return error_response(404, "not_found", f"DNS policy '{policy_id}' not found")


@app.route("/v1/sites/<site_id>/dns/policies/<policy_id>", methods=["DELETE"])
def delete_dns_policy(site_id, policy_id):
    with lock:
        policies = dns_policies.get(site_id, [])
        for i, p in enumerate(policies):
            if p["id"] == policy_id:
                policies.pop(i)
                log_event("DELETE", "dns_policy", policy_id)
                return "", 204
    return error_response(404, "not_found", f"DNS policy '{policy_id}' not found")


# Firewall Policy Ordering (stub)
@app.route("/v1/sites/<site_id>/firewall/policy/ordering", methods=["GET"])
def get_fw_ordering(site_id):
    with lock:
        ids = [p["id"] for p in fw_policies.get(site_id, [])]
    return jsonify({"data": ids})


@app.route("/v1/sites/<site_id>/firewall/policy/ordering", methods=["PUT"])
def set_fw_ordering(site_id):
    return jsonify({"data": request.get_json()})


# ---------------------------------------------------------------------------
# SSE endpoint for live updates
# ---------------------------------------------------------------------------

@app.route("/sse")
def sse_stream():
    q: queue.Queue = queue.Queue(maxsize=50)
    sse_subscribers.append(q)

    def generate():
        # Send initial snapshot
        yield f"data: {json.dumps(build_snapshot())}\n\n"
        while True:
            try:
                data = q.get(timeout=30)
                yield f"data: {data}\n\n"
            except queue.Empty:
                # Heartbeat
                yield ": heartbeat\n\n"

    return Response(generate(), mimetype="text/event-stream")


# ---------------------------------------------------------------------------
# Web UI
# ---------------------------------------------------------------------------

@app.route("/ui")
def dashboard():
    return DASHBOARD_HTML


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>UniFi Mock API Dashboard</title>
<style>
  :root {
    --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3a;
    --text: #e4e6eb; --muted: #8b8fa3; --accent: #4f8ff7;
    --green: #34d399; --red: #f87171; --yellow: #fbbf24; --blue: #60a5fa;
    --purple: #a78bfa;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'SF Mono', 'Fira Code', monospace; background: var(--bg); color: var(--text); font-size: 13px; }

  .header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 12px 24px; display: flex; align-items: center; gap: 16px; }
  .header h1 { font-size: 16px; font-weight: 600; }
  .header .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); animation: pulse 2s infinite; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

  .stats { display: flex; gap: 8px; margin-left: auto; }
  .stat { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 6px 12px; text-align: center; }
  .stat .num { font-size: 20px; font-weight: 700; color: var(--accent); }
  .stat .label { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }

  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; padding: 16px 24px; }
  @media (max-width: 1200px) { .grid { grid-template-columns: 1fr; } }

  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  .card-header { padding: 10px 14px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 8px; }
  .card-header h2 { font-size: 13px; font-weight: 600; }
  .card-header .count { background: var(--bg); border: 1px solid var(--border); border-radius: 10px; padding: 1px 8px; font-size: 11px; color: var(--muted); }
  .card-body { padding: 0; max-height: 350px; overflow-y: auto; }

  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 6px 14px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); background: var(--bg); position: sticky; top: 0; }
  td { padding: 6px 14px; border-top: 1px solid var(--border); }
  tr:hover td { background: rgba(79, 143, 247, 0.05); }

  .id { color: var(--muted); font-size: 11px; }
  .enabled { color: var(--green); }
  .disabled { color: var(--red); }

  .badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; }
  .badge-create { background: rgba(52, 211, 153, 0.15); color: var(--green); }
  .badge-read { background: rgba(96, 165, 250, 0.15); color: var(--blue); }
  .badge-list { background: rgba(167, 139, 250, 0.15); color: var(--purple); }
  .badge-update { background: rgba(251, 191, 36, 0.15); color: var(--yellow); }
  .badge-delete { background: rgba(248, 113, 113, 0.15); color: var(--red); }
  .badge-patch { background: rgba(251, 191, 36, 0.15); color: var(--yellow); }
  .badge-error { background: rgba(248, 113, 113, 0.15); color: var(--red); }

  .event-log { padding: 0; }
  .event-log .card-body { max-height: 280px; }
  .event { padding: 4px 14px; border-top: 1px solid var(--border); display: flex; gap: 10px; align-items: center; font-size: 12px; }
  .event .time { color: var(--muted); min-width: 80px; }
  .event .type { min-width: 80px; color: var(--muted); }
  .event .resource-id { color: var(--accent); }

  .full-width { grid-column: 1 / -1; }

  .empty { color: var(--muted); padding: 20px; text-align: center; font-style: italic; }

  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: var(--surface); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
</style>
</head>
<body>

<div class="header">
  <div class="dot"></div>
  <h1>UniFi Mock API</h1>
  <div class="stats" id="stats"></div>
</div>

<div class="grid">
  <div class="card">
    <div class="card-header"><h2>Firewall Policies</h2><span class="count" id="fw-count">0</span></div>
    <div class="card-body"><table><thead><tr><th>ID</th><th>Name</th><th>Action</th><th>Enabled</th></tr></thead><tbody id="fw-table"></tbody></table></div>
  </div>

  <div class="card">
    <div class="card-header"><h2>DNS Policies</h2><span class="count" id="dns-count">0</span></div>
    <div class="card-body"><table><thead><tr><th>ID</th><th>Domain</th><th>Type</th><th>Enabled</th></tr></thead><tbody id="dns-table"></tbody></table></div>
  </div>

  <div class="card">
    <div class="card-header"><h2>Firewall Zones</h2><span class="count" id="zone-count">0</span></div>
    <div class="card-body"><table><thead><tr><th>ID</th><th>Name</th><th>Networks</th></tr></thead><tbody id="zone-table"></tbody></table></div>
  </div>

  <div class="card">
    <div class="card-header"><h2>Networks</h2><span class="count" id="net-count">0</span></div>
    <div class="card-body"><table><thead><tr><th>ID</th><th>Name</th><th>VLAN</th></tr></thead><tbody id="net-table"></tbody></table></div>
  </div>

  <div class="card full-width event-log">
    <div class="card-header"><h2>Event Log</h2><span class="count" id="event-count">0</span></div>
    <div class="card-body" id="event-body"></div>
  </div>
</div>

<script>
const source = new EventSource('/sse');

source.onmessage = (e) => {
  const data = JSON.parse(e.data);
  render(data);
};

source.onerror = () => {
  document.querySelector('.dot').style.background = '#f87171';
};

function render(data) {
  // Stats
  const s = data.stats;
  document.getElementById('stats').innerHTML = `
    <div class="stat"><div class="num">${s.total_fw_policies}</div><div class="label">FW Policies</div></div>
    <div class="stat"><div class="num">${s.total_dns_policies}</div><div class="label">DNS Policies</div></div>
    <div class="stat"><div class="num">${s.total_zones}</div><div class="label">Zones</div></div>
    <div class="stat"><div class="num">${s.total_networks}</div><div class="label">Networks</div></div>
  `;

  // FW Policies
  const fwPolicies = Object.values(data.fw_policies).flat();
  document.getElementById('fw-count').textContent = fwPolicies.length;
  document.getElementById('fw-table').innerHTML = fwPolicies.length === 0
    ? '<tr><td colspan="4" class="empty">No firewall policies yet. Run terraform apply...</td></tr>'
    : fwPolicies.map(p => `<tr>
        <td class="id">${p.id}</td>
        <td>${p.name || '-'}</td>
        <td>${p.action?.type || '-'}</td>
        <td class="${p.enabled ? 'enabled' : 'disabled'}">${p.enabled ? 'Yes' : 'No'}</td>
      </tr>`).join('');

  // DNS Policies
  const dnsPolicies = Object.values(data.dns_policies).flat();
  document.getElementById('dns-count').textContent = dnsPolicies.length;
  document.getElementById('dns-table').innerHTML = dnsPolicies.length === 0
    ? '<tr><td colspan="4" class="empty">No DNS policies yet. Run terraform apply...</td></tr>'
    : dnsPolicies.map(p => `<tr>
        <td class="id">${p.id}</td>
        <td>${p.domain || '-'}</td>
        <td>${p.type || '-'}</td>
        <td class="${p.enabled ? 'enabled' : 'disabled'}">${p.enabled ? 'Yes' : 'No'}</td>
      </tr>`).join('');

  // Zones
  const allZones = Object.values(data.zones).flat();
  document.getElementById('zone-count').textContent = allZones.length;
  document.getElementById('zone-table').innerHTML = allZones.map(z => `<tr>
    <td class="id">${z.id}</td>
    <td>${z.name}</td>
    <td class="id">${(z.networkIds || []).join(', ') || '-'}</td>
  </tr>`).join('');

  // Networks
  const allNets = Object.values(data.networks).flat();
  document.getElementById('net-count').textContent = allNets.length;
  document.getElementById('net-table').innerHTML = allNets.map(n => `<tr>
    <td class="id">${n.id}</td>
    <td>${n.name}</td>
    <td>${n.vlanId}</td>
  </tr>`).join('');

  // Events
  const events = (data.events || []).reverse();
  document.getElementById('event-count').textContent = events.length;
  const badgeClass = {CREATE: 'badge-create', READ: 'badge-read', LIST: 'badge-list', UPDATE: 'badge-update', DELETE: 'badge-delete', PATCH: 'badge-patch', ERROR: 'badge-error'};
  document.getElementById('event-body').innerHTML = events.map(ev => `
    <div class="event">
      <span class="time">${ev.time}</span>
      <span class="badge ${badgeClass[ev.action] || ''}">${ev.action}</span>
      <span class="type">${ev.resource_type}</span>
      <span class="resource-id">${ev.resource_id}</span>
      <span>${ev.detail || ''}</span>
    </div>
  `).join('');
}
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  UniFi Mock API Server")
    print("=" * 60)
    print(f"  API:       http://localhost:5100")
    print(f"  Dashboard: http://localhost:5100/ui")
    print(f"  Site ID:   site-default")
    print(f"  API Key:   any non-empty string")
    print()
    print("  Terraform provider config:")
    print('    provider "unifi" {')
    print('      host     = "http://localhost:5100"')
    print('      api_key  = "mock-key"')
    print('      site_id  = "auto"')
    print('      insecure = true')
    print("    }")
    print("=" * 60)
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()
    app.run(host="0.0.0.0", port=5100, debug=args.debug)
