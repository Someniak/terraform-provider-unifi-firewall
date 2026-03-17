# 1. Create a custom zone with no networks
resource "unifi_firewall_zone" "cameras" {
  name = "Cameras"
}

# 2. Create a custom zone and assign a single network
resource "unifi_firewall_zone" "servers" {
  name        = "Servers"
  network_ids = [data.unifi_network.testiot.id]
}

# 3. Create a custom zone with multiple networks
resource "unifi_firewall_zone" "multi_net" {
  name        = "MultiNet"
  network_ids = [data.unifi_network.testiot.id, data.unifi_network.testguest.id]
}
