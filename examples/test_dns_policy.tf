resource "unifi_dns" "test_policy" {
  type    = "A_RECORD"
  domain  = "example.com"
  enabled = true
  ttl     = 3600
  ip_address = "127.0.0.1" # Using loopback as sinkhole for testing
}
