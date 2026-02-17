# Fetch common firewall zones
data "unifi_firewall_zone" "default" {
  name = "Default"
}

data "unifi_firewall_zone" "internet" {
  name = "External"
}

data "unifi_firewall_zone" "guest" {
  name = "Guest"
}

data "unifi_firewall_zone" "iot" {
  name = "IoT"
}
