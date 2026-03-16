# Assign a fixed IP (DHCP reservation) to a client device.
resource "unifi_fixedip" "server" {
  mac        = "00:11:22:33:44:55"
  network_id = "net-1"
  fixed_ip   = "192.168.1.100"
  name       = "my-server"
}
