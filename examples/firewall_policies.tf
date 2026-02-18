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
    time_range {
      start = "08:00"
      stop  = "17:00"
    }
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
    traffic_filter {
      type = "NETWORK"
      network_filter {
        type           = "NETWORKS"
        match_opposite = false
        items          = ["iot-network-id"] # Replace with valid ID
      }
    }
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
