# UniFi Firewall Policy Terraform Examples

This guide provides an overview of the example firewall policies included in `firewall_policies.tf`. These examples demonstrate various features of the UniFi Firewall resource.

## Prerequisites

Ensure you have defined the necessary `unifi_firewall_zone` data sources in your configuration, as shown in `data.tf`:
- `data.unifi_firewall_zone.default`: Reference to main/LAN network.
- `data.unifi_firewall_zone.internet`: Reference to WAN/Internet.
- `data.unifi_firewall_zone.guest`: Reference to Guest network.
- `data.unifi_firewall_zone.iot`: Reference to IoT network.

## Examples

### 1. Basic Allow Rule (`allow_internet`)
A simple rule allowing traffic from your internal network (Default) to the Internet.
- **Action:** ALLOW
- **Return Traffic:** Implicitly `true` (default for ALLOW).

### 2. Scheduled Blocking (`block_guest_iot_workhours`)
Demonstrates how to apply rules based on a schedule. This rule blocks Guest access to IoT devices during specific hours.
- **Schedule:** Mondays-Fridays, 08:00 - 17:00.
- **Action:** BLOCK
- **Return Traffic:** Implicitly `false` (default for BLOCK).

### 3. Port Filtering - Specific Ports (`allow_admin_access`)
Allows access only on specific ports (SSH/22, HTTP/80).
- **Filter Type:** PORT
- **Items:** List of individual port numbers.

### 4. Port Filtering - Ranges (`allow_app_ports`)
Allows a continuous range of ports (8080-8090).
- **Filter Type:** PORT
- **Items:** `PORT_NUMBER_RANGE` with `start` and `stop` values.

### 5. Domain Filtering (`block_social_media`)
Blocks access to specific domain names.
- **Filter Type:** DOMAIN
- **Items:** List of domains (e.g., facebook.com).
- **Destination:** Internet zone.

### 6. Specific IP Filtering (`block_bad_ip`)
Blocks traffic from a specific internal IP address.
- **Filter Type:** IP_ADDRESS
- **Items:** List of IP addresses.

### 7. Protocol Filtering (`block_ping`)
Blocks ICMP traffic (ping) between networks.
- **Protocol:** icmp
- **Scope:** IPV4

### 8. MAC Address Filtering (`block_specific_mac`)
Blocks traffic from a specific device identified by its MAC address.
- **Filter Type:** MAC_ADDRESS
- **Items:** List of MAC addresses.

### 9. Connection State Filtering (`allow_established`)
Matches traffic based on connection state (ESTABLISHED, RELATED). Useful for allowing return traffic for initiated connections.

### 10. Combined IP Filtering (`block_specific_ip_pair`)
Blocks traffic from a specific Source IP to a specific Destination IP.
- **Source Filter:** IP_ADDRESS
- **Destination Filter:** IP_ADDRESS

### 11. Source IP and Port Filtering (`block_specific_source_port`)
Blocks traffic from a specific IP **originating** from specific ports.
- **Source Filter:** Combined IP_ADDRESS and PORT.
- **Note:** The `type` must be set to one of the filters (e.g., `IP_ADDRESS`), but other sub-blocks like `port_filter` can be provided alongside it.

### 12. Complex Access Control (`limit_iot_server_access`)
Limits a whole network (e.g., IoT) to accessing a specific server IP on a specific port (e.g., MQTT).
- **Source:** NETWORK filter.
- **Destination:** Combined IP_ADDRESS and PORT filter.

## Usage

To apply these rules, ensure your `terraform.tfvars` contains valid `unifi_host`, `unifi_api_key`, and `unifi_site_id`.

```bash
terraform init
terraform apply
```
