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

data "unifi_firewall_zone" "dmz" {
  name = "DMZ"
}

# Fetch test networks created by the integration server
data "unifi_network" "testiot" {
  name = "TestIoT"
}

data "unifi_network" "testguest" {
  name = "TestGuest"
}
