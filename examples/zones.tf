# 1. Create a custom zone with no networks
resource "unifi_firewall_zone" "cameras" {
  name = "Cameras"
}

# 2. Create a custom zone and assign networks to it
resource "unifi_firewall_zone" "servers" {
  name        = "Servers"
  network_ids = [data.unifi_network.testiot.id]
}
