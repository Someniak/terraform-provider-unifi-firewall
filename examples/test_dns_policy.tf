# A Record
resource "unifi_dns" "test_a_record" {
  type       = "A_RECORD"
  domain     = "example.com"
  enabled    = true
  ttl        = 3600
  ip_address = "127.0.0.1"
}

# AAAA Record (IPv6)
resource "unifi_dns" "test_aaaa_record" {
  type       = "AAAA_RECORD"
  domain     = "ipv6.example.com"
  enabled    = true
  ttl        = 3600
  ip_address = "::1"
}

# CNAME Record
resource "unifi_dns" "test_cname_record" {
  type    = "CNAME_RECORD"
  domain  = "www.example.com"
  enabled = true
  ttl     = 3600
  cname   = "example.com"
}

# MX Record
resource "unifi_dns" "test_mx_record" {
  type        = "MX_RECORD"
  domain      = "example.com"
  enabled     = true
  ttl         = 3600
  mail_server = "mail.example.com"
  priority    = 10
}

# TXT Record
resource "unifi_dns" "test_txt_record" {
  type    = "TXT_RECORD"
  domain  = "example.com"
  enabled = true
  ttl     = 3600
  text    = "v=spf1 include:example.com ~all"
}

# SRV Record
resource "unifi_dns" "test_srv_record" {
  type          = "SRV_RECORD"
  domain        = "example.com"
  enabled       = true
  ttl           = 3600
  service       = "_ldap"
  protocol      = "_tcp"
  server_domain = "ldap.example.com"
  port          = 389
  weight        = 100
  priority      = 10
}

# Forward Domain (conditional DNS forwarding)
resource "unifi_dns" "test_forward_domain" {
  type       = "FORWARD_DOMAIN"
  domain     = "corp.example.com"
  enabled    = true
  ip_address = "10.0.0.53"
}

# Disabled DNS Policy
resource "unifi_dns" "test_disabled_record" {
  type       = "A_RECORD"
  domain     = "disabled.example.com"
  enabled    = false
  ttl        = 300
  ip_address = "192.168.1.1"
}
