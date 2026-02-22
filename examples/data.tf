# Fetch common firewall zones
data "unifi_firewall_zone" "default" {
  name = "Internal"
}

data "unifi_firewall_zone" "internet" {
  name = "External"
}

data "unifi_firewall_zone" "guest" {
  name = "Hotspot"
}

data "unifi_firewall_zone" "iot" {
  name = "IoT"
}
