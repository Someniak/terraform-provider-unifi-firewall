# 1. Basic Allow Rule
# Allows traffic from Default zone to Internet
resource "unifi_fw" "allow_internet" {
  name    = "Allow Internet Access"
  enabled = true
  action {
    type                 = "ALLOW"
  }
  source {
    zone_id = data.unifi_firewall_zone.default.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.internet.id
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = true
}

# 2. Block Rule with Scheduling
# Blocks Guest access to IoT between 8am and 5pm on weekdays
resource "unifi_fw" "block_guest_iot_workhours" {
  name    = "Block Guest to IoT (Work Hours)"
  enabled = true
  action {
    type                 = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.guest.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.iot.id
  }
  schedule {
    mode         = "EVERY_WEEK"
    days_of_week = ["MON", "TUE", "WED", "THU", "FRI"]
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = true
}

# 3. Port Filtering (Specific Ports)
# Allows SSH and HTTP from Default to IoT
resource "unifi_fw" "allow_admin_access" {
  name    = "Allow Admin Access"
  enabled = true
  action {
    type                 = "ALLOW"
  }
  source {
    zone_id = data.unifi_firewall_zone.default.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.iot.id
    traffic_filter {
      type = "PORT"
      port_filter {
        type           = "PORTS"
        match_opposite = false
        items {
          type  = "PORT_NUMBER"
          value = 22
        }
        items {
          type  = "PORT_NUMBER"
          value = 80
        }
      }
    }
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = true
}

# 4. Port Filtering (Ranges)
# Allows a range of ports for specific application
resource "unifi_fw" "allow_app_ports" {
  name    = "Allow App Ports"
  enabled = true
  action {
    type                 = "ALLOW"
  }
  source {
    zone_id = data.unifi_firewall_zone.default.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.iot.id
    traffic_filter {
      type = "PORT"
      port_filter {
        type           = "PORTS"
        match_opposite = false
        items {
          type  = "PORT_NUMBER_RANGE"
          start = 8080
          stop  = 8090
        }
      }
    }
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = false
}

# 4b. Protocol and Port Filtering (UDP Ports)
# Allows specific UDP ports (e.g., DNS, NTP) from Default to Internet
resource "unifi_fw" "allow_udp_services" {
  name    = "Allow UDP Services"
  enabled = true
  action {
    type                 = "ALLOW"
  }
  source {
    zone_id = data.unifi_firewall_zone.default.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.internet.id
    traffic_filter {
      type = "PORT"
      port_filter {
        type           = "PORTS"
        match_opposite = false
        items {
          type  = "PORT_NUMBER"
          value = 53 # DNS
        }
        items {
          type  = "PORT_NUMBER"
          value = 123 # NTP
        }
      }
    }
  }
  ip_protocol_scope {
    ip_version = "IPV4"
    protocol_filter {
      type           = "PROTOCOL"
      match_opposite = false
      protocol       = "udp"
    }
  }
  logging_enabled = false
}

# 5. Domain Filtering (Block Social Media)
# Blocks access to specific domains
resource "unifi_fw" "block_social_media" {
  name    = "Block Social Media"
  enabled = true
  action {
    type                 = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.guest.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.internet.id
    traffic_filter {
      type = "DOMAIN"
      domain_filter {
        items = ["facebook.com", "instagram.com", "twitter.com"]
      }
    }
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = true
}

# 6. Specific IP Filtering
# Block specific IP from accessing internet
resource "unifi_fw" "block_bad_ip" {
  name    = "Block Bad IP"
  enabled = true
  action {
    type                 = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.guest.id
    traffic_filter {
      type = "IP_ADDRESS"
      ip_address_filter {
        type           = "IP_ADDRESSES"
        match_opposite = false
        items          = ["192.168.2.100"]
      }
    }
  }
  destination {
    zone_id = data.unifi_firewall_zone.internet.id
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = true
}

# 7. Protocol Filtering (Block ICMP/Ping)
resource "unifi_fw" "block_ping" {
  name    = "Block Ping"
  enabled = true
  action {
    type                 = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.guest.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.default.id
  }
  ip_protocol_scope {
    ip_version = "IPV4"
    protocol_filter {
      type           = "PROTOCOL"
      match_opposite = false
      protocol       = "icmp"
    }
  }
  logging_enabled = false
}

# 8. MAC Address Filtering
resource "unifi_fw" "block_specific_mac" {
  name    = "Block Device by MAC"
  enabled = true
  action {
    type                 = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.guest.id
    traffic_filter {
      type = "MAC_ADDRESS"
      mac_address_filter {
        type           = "MAC_ADDRESSES"
        match_opposite = false
        items          = ["00:11:22:33:44:55"]
      }
    }
  }
  destination {
    zone_id = data.unifi_firewall_zone.internet.id
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = true
}

# 9. Connection State Filtering
# Allow established/related traffic
resource "unifi_fw" "allow_established" {
  name    = "Allow Established"
  enabled = true
  action {
    type                 = "ALLOW"
  }
  source {
    zone_id = data.unifi_firewall_zone.internet.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.default.id
  }
  connection_state_filter = ["ESTABLISHED", "RELATED"]
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = false
}

# 10. Combined Filter: Source IP + Destination IP
# Blocks traffic from a specific Source IP to a specific Destination IP
resource "unifi_fw" "block_specific_ip_pair" {
  name    = "Block IP Pair"
  enabled = true
  action {
    type = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.default.id
    traffic_filter {
      type = "IP_ADDRESS"
      ip_address_filter {
        type           = "IP_ADDRESSES"
        match_opposite = false
        items          = ["192.168.1.50"]
      }
    }
  }
  destination {
    zone_id = data.unifi_firewall_zone.iot.id
    traffic_filter {
      type = "IP_ADDRESS"
      ip_address_filter {
        type           = "IP_ADDRESSES"
        match_opposite = false
        items          = ["192.168.20.10"]
      }
    }
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = true
}

# 11. Combined Filter: Source IP + Source Port
# Blocks traffic from a specific IP originating from specific ports
# Note: Combining multiple filters in one traffic_filter block
resource "unifi_fw" "block_specific_source_port" {
  name    = "Block Specific Source"
  enabled = true
  action {
    type = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.guest.id
    traffic_filter {
      type = "IP_ADDRESS" # Primary type
      ip_address_filter {
        type           = "IP_ADDRESSES"
        match_opposite = false
        items          = ["10.0.0.100"]
      }
      port_filter {
        type           = "PORTS"
        match_opposite = false
        items {
          type  = "PORT_NUMBER"
          value = 8080
        }
      }
    }
  }
  destination {
    zone_id = data.unifi_firewall_zone.internet.id
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = true
}

# 12. Complex Rule: Source Network + Dest Port + Dest IP
# Limits a whole network to accessing a specific server on a specific port
resource "unifi_fw" "limit_iot_server_access" {
  name    = "Limit IoT Server Access"
  enabled = true
  action {
    type                 = "ALLOW"
  }
  source {
    zone_id = data.unifi_firewall_zone.iot.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.default.id
    traffic_filter {
      type = "IP_ADDRESS"
      ip_address_filter {
        type           = "IP_ADDRESSES"
        match_opposite = false
        items          = ["192.168.1.10"]
      }
      port_filter {
        type           = "PORTS"
        match_opposite = false
        items {
          type  = "PORT_NUMBER"
          value = 1883 # MQTT
        }
      }
    }
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = true
}

# 13. Reject Action with Description
# Rejects IoT traffic to Internal with an ICMP unreachable response
resource "unifi_fw" "reject_iot_to_internal" {
  name        = "Reject IoT to Internal"
  description = "Reject IoT devices from accessing internal resources with ICMP unreachable"
  enabled     = true
  action {
    type = "REJECT"
  }
  source {
    zone_id = data.unifi_firewall_zone.iot.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.default.id
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = true
}

# 14. Allow Return Traffic
# Allows Internal to IoT with automatic return traffic tracking
resource "unifi_fw" "allow_internal_to_iot_return" {
  name    = "Allow Internal to IoT (Return Traffic)"
  enabled = true
  action {
    type                 = "ALLOW"
    allow_return_traffic = true
  }
  source {
    zone_id = data.unifi_firewall_zone.default.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.iot.id
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = false
}

# 15. Network Filter with Match Opposite (Inverse)
# Block all source networks EXCEPT TestIoT from reaching IoT zone
resource "unifi_fw" "block_except_iot_network" {
  name    = "Block Non-IoT Networks"
  enabled = true
  action {
    type = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.default.id
    traffic_filter {
      type = "NETWORK"
      network_filter {
        type           = "NETWORKS"
        match_opposite = true
        items          = [data.unifi_network.testiot.id]
      }
    }
  }
  destination {
    zone_id = data.unifi_firewall_zone.iot.id
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = true
}

# 16. IPv4 and IPv6 Dual-Stack Rule
# Block Guest to DMZ on both IPv4 and IPv6
resource "unifi_fw" "block_guest_dmz_dualstack" {
  name    = "Block Guest to DMZ (Dual-Stack)"
  enabled = true
  action {
    type = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.guest.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.dmz.id
  }
  ip_protocol_scope {
    ip_version = "IPV4_AND_IPV6"
  }
  logging_enabled = true
}

# 17. IPsec Filter
# Allow only IPsec-encrypted traffic from Internal to External
resource "unifi_fw" "allow_ipsec_traffic" {
  name    = "Allow IPsec Encrypted Traffic"
  enabled = true
  action {
    type = "ALLOW"
  }
  source {
    zone_id = data.unifi_firewall_zone.default.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.internet.id
  }
  ipsec_filter = "MATCH_ENCRYPTED"
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = false
}

# 18. Schedule with Time Range
# Block Guest internet access in the evenings (6pm-6am) on weekdays
resource "unifi_fw" "block_guest_evenings" {
  name    = "Block Guest Internet (Evenings)"
  enabled = true
  action {
    type = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.guest.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.internet.id
  }
  schedule {
    mode         = "EVERY_WEEK"
    days_of_week = ["MON", "TUE", "WED", "THU", "FRI"]
    time_range {
      start = "18:00"
      stop  = "06:00"
    }
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = true
}

# 19. EVERY_DAY Schedule Mode
# Block IoT internet access every day during a time window
resource "unifi_fw" "block_iot_daily" {
  name    = "Block IoT Internet (Daily)"
  enabled = true
  action {
    type = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.iot.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.internet.id
  }
  schedule {
    mode = "EVERY_DAY"
    time_range {
      start = "22:00"
      stop  = "06:00"
    }
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = false
}

# 20. ONE_TIME_ONLY Schedule Mode
# Temporary maintenance window block
resource "unifi_fw" "maintenance_block" {
  name    = "Maintenance Window Block"
  enabled = true
  action {
    type = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.guest.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.default.id
  }
  schedule {
    mode  = "ONE_TIME_ONLY"
    start = "2026-04-01T00:00:00"
    stop  = "2026-04-01T06:00:00"
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = true
}

# 21. Connection State: NEW and INVALID
# Block new and invalid connections from Guest to Internal
resource "unifi_fw" "block_new_invalid_connections" {
  name                    = "Block New/Invalid Guest Connections"
  enabled                 = true
  connection_state_filter = ["NEW", "INVALID"]
  action {
    type = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.guest.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.default.id
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = true
}

# 22. MATCH_NOT_ENCRYPTED IPsec Filter
# Block unencrypted traffic from Internal to DMZ
resource "unifi_fw" "block_unencrypted_to_dmz" {
  name    = "Block Unencrypted to DMZ"
  enabled = true
  action {
    type = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.default.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.dmz.id
  }
  ipsec_filter = "MATCH_NOT_ENCRYPTED"
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = true
}

# 23. IPv6-Only Rule
# Block IoT to Internal on IPv6 only
resource "unifi_fw" "block_iot_internal_ipv6" {
  name    = "Block IoT to Internal (IPv6)"
  enabled = true
  action {
    type = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.iot.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.default.id
  }
  ip_protocol_scope {
    ip_version = "IPV6"
  }
  logging_enabled = false
}

# 24. Disabled Firewall Rule
# A rule that exists but is intentionally disabled
resource "unifi_fw" "disabled_rule" {
  name    = "Disabled Placeholder Rule"
  enabled = false
  action {
    type = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.guest.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.default.id
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = false
}

# 25. Port Filter with match_opposite (Inverse Port Match)
# Block all traffic EXCEPT HTTP/HTTPS from Guest to Internet
resource "unifi_fw" "block_non_web_guest" {
  name    = "Block Non-Web Guest Traffic"
  enabled = true
  action {
    type = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.guest.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.internet.id
    traffic_filter {
      type = "PORT"
      port_filter {
        type           = "PORTS"
        match_opposite = true
        items {
          type  = "PORT_NUMBER"
          value = 80
        }
        items {
          type  = "PORT_NUMBER"
          value = 443
        }
      }
    }
  }
  ip_protocol_scope {
    ip_version = "IPV4"
    protocol_filter {
      type     = "PROTOCOL"
      protocol = "tcp"
    }
  }
  logging_enabled = true
}

# 26. IP Address Filter with match_opposite (Inverse IP Match)
# Allow only a specific IP to reach IoT zone
resource "unifi_fw" "block_non_admin_to_iot" {
  name    = "Block Non-Admin to IoT"
  enabled = true
  action {
    type = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.default.id
    traffic_filter {
      type = "IP_ADDRESS"
      ip_address_filter {
        type           = "IP_ADDRESSES"
        match_opposite = true
        items          = ["192.168.10.100"]
      }
    }
  }
  destination {
    zone_id = data.unifi_firewall_zone.iot.id
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = true
}

# 27. Protocol Filter with match_opposite
# Block everything except TCP from IoT to Internet
resource "unifi_fw" "block_non_tcp_iot" {
  name    = "Block Non-TCP IoT Traffic"
  enabled = true
  action {
    type = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.iot.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.internet.id
  }
  ip_protocol_scope {
    ip_version = "IPV4"
    protocol_filter {
      type           = "PROTOCOL"
      protocol       = "tcp"
      match_opposite = true
    }
  }
  logging_enabled = true
}

# 28. Destination Network Filter
# Block traffic to specific destination networks in the DMZ
resource "unifi_fw" "block_to_dmz_network" {
  name    = "Block to DMZ Network"
  enabled = true
  action {
    type = "BLOCK"
  }
  source {
    zone_id = data.unifi_firewall_zone.guest.id
  }
  destination {
    zone_id = data.unifi_firewall_zone.dmz.id
    traffic_filter {
      type = "NETWORK"
      network_filter {
        type  = "NETWORKS"
        items = [data.unifi_network.testguest.id]
      }
    }
  }
  ip_protocol_scope {
    ip_version = "IPV4"
  }
  logging_enabled = true
}
