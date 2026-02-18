package unifi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type Client struct {
	BaseURL    string
	APIKey     string
	SiteID     string
	Insecure   bool
	HTTPClient *http.Client
}

func NewClient(baseUrl, apiKey, siteId string, insecure bool) *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
	return &Client{
		BaseURL:  baseUrl,
		APIKey:   apiKey,
		SiteID:   siteId,
		Insecure: insecure,
		HTTPClient: &http.Client{
			Timeout:   time.Minute,
			Transport: tr,
		},
	}
}

func (c *Client) doRequest(req *http.Request) ([]byte, error) {
	req.Header.Set("X-API-Key", c.APIKey)
	req.Header.Set("Accept", "application/json")
	if req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("api error: status %d, body: %s", res.StatusCode, string(body))
	}

	return body, nil
}

// Sites
type Site struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	InternalReference string `json:"internalReference"`
}

func (c *Client) ListSites() ([]Site, error) {
	url := fmt.Sprintf("%s/v1/sites", c.BaseURL)
	req, _ := http.NewRequest(http.MethodGet, url, nil)

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var response struct {
		Data []Site `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal sites: %w. response body: %s", err, string(body))
	}

	return response.Data, nil
}

// Firewall Zones
type FirewallZone struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	NetworkIDs []string `json:"networkIds"`
}

func (c *Client) ListFirewallZones() ([]FirewallZone, error) {
	url := fmt.Sprintf("%s/v1/sites/%s/firewall/zones", c.BaseURL, c.SiteID)
	req, _ := http.NewRequest(http.MethodGet, url, nil)

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var response struct {
		Data []FirewallZone `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal firewall zones: %w. response body: %s", err, string(body))
	}

	return response.Data, nil
}

// Firewall Policies
type FirewallPolicy struct {
	ID                    string             `json:"id,omitempty"`
	Enabled               bool               `json:"enabled"`
	Name                  string             `json:"name"`
	Description           string             `json:"description,omitempty"`
	Action                FirewallAction     `json:"action"`
	Source                FirewallSourceDest `json:"source"`
	Destination           FirewallSourceDest `json:"destination"`
	IPProtocolScope       IPProtocolScope    `json:"ipProtocolScope"`
	ConnectionStateFilter []string           `json:"connectionStateFilter,omitempty"`
	IPsecFilter           string             `json:"ipsecFilter,omitempty"`
	LoggingEnabled        bool               `json:"loggingEnabled"`
	Schedule              *FirewallSchedule  `json:"schedule,omitempty"`
}

type FirewallAction struct {
	Type               string `json:"type"` // e.g., "ALLOW", "BLOCK", "REJECT"
	AllowReturnTraffic bool   `json:"allowReturnTraffic"`
}

type FirewallSourceDest struct {
	ZoneID        string         `json:"zoneId"`
	TrafficFilter *TrafficFilter `json:"trafficFilter,omitempty"`
}

type TrafficFilter struct {
	Type             string           `json:"type"` // PORT, NETWORK, MAC_ADDRESS, IP_ADDRESS, IPV6_IID, REGION, VPN_SERVER, SITE_TO_SITE_VPN_TUNNEL, DOMAIN (dest only), APPLICATION (dest only)
	PortFilter       *PortFilter      `json:"portFilter,omitempty"`
	DomainFilter     *DomainFilter    `json:"domainFilter,omitempty"`
	IPAddressFilter  *IPAddressFilter `json:"ipAddressFilter,omitempty"`
	NetworkFilter    *NetworkFilter   `json:"networkFilter,omitempty"`
	MACAddressFilter interface{}      `json:"macAddressFilter,omitempty"` // Polymorphic: string (additional) or *MACAddressFilter (standalone)
}

type IPAddressFilter struct {
	Type          string          `json:"type"` // IP_ADDRESSES, TRAFFIC_MATCHING_LIST
	MatchOpposite bool            `json:"matchOpposite"`
	Items         []IPAddressItem `json:"items"`
}

type IPAddressItem struct {
	Type  string `json:"type"` // IP_ADDRESS, SUBNET, IP_ADDRESS_RANGE
	Value string `json:"value"`
}

type MACAddressFilter struct {
	MACAddresses []string `json:"macAddresses"`
}

type NetworkFilter struct {
	MatchOpposite bool     `json:"matchOpposite"`
	NetworkIDs    []string `json:"networkIds"`
}

type DomainFilter struct {
	Type    string   `json:"type"` // DOMAINS
	Domains []string `json:"domains"`
}

type PortFilter struct {
	Type          string     `json:"type"` // PORTS, TRAFFIC_MATCHING_LIST
	MatchOpposite bool       `json:"matchOpposite"`
	Items         []PortItem `json:"items"`
}

type PortItem struct {
	Type  string `json:"type"` // PORT_NUMBER, PORT_NUMBER_RANGE
	Value int    `json:"value,omitempty"`
	Start int    `json:"start,omitempty"`
	Stop  int    `json:"stop,omitempty"`
}

type IPProtocolScope struct {
	IPVersion      string          `json:"ipVersion"` // "IPV4", "IPV6", "IPV4_AND_IPV6"
	ProtocolFilter *ProtocolFilter `json:"protocolFilter,omitempty"`
}

type ProtocolFilter struct {
	Type          string                 `json:"type"` // NAMED_PROTOCOL, PROTOCOL_NUMBER, PRESET
	Protocol      map[string]interface{} `json:"protocol,omitempty"`
	MatchOpposite bool                   `json:"matchOpposite"`
}

type FirewallSchedule struct {
	Mode       string `json:"mode"` // EVERY_DAY, EVERY_WEEK, ONE_TIME_ONLY, CUSTOM
	TimeFilter any    `json:"timeFilter"`
}

func (c *Client) CreateFirewallPolicy(policy FirewallPolicy) (*FirewallPolicy, error) {
	url := fmt.Sprintf("%s/v1/sites/%s/firewall/policies", c.BaseURL, c.SiteID)
	payload, _ := json.Marshal(policy)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(payload))

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var result FirewallPolicy
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) GetFirewallPolicy(policyId string) (*FirewallPolicy, error) {
	url := fmt.Sprintf("%s/v1/sites/%s/firewall/policies/%s", c.BaseURL, c.SiteID, policyId)
	req, _ := http.NewRequest(http.MethodGet, url, nil)

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var result FirewallPolicy
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) UpdateFirewallPolicy(policyId string, policy FirewallPolicy) (*FirewallPolicy, error) {
	url := fmt.Sprintf("%s/v1/sites/%s/firewall/policies/%s", c.BaseURL, c.SiteID, policyId)
	payload, _ := json.Marshal(policy)
	req, _ := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(payload))

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var result FirewallPolicy
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) DeleteFirewallPolicy(policyId string) error {
	url := fmt.Sprintf("%s/v1/sites/%s/firewall/policies/%s", c.BaseURL, c.SiteID, policyId)
	req, _ := http.NewRequest(http.MethodDelete, url, nil)
	_, err := c.doRequest(req)
	return err
}

// Networks
type Network struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	VlanID     int    `json:"vlanId"`
	Management string `json:"management"`
}

func (c *Client) ListNetworks() ([]Network, error) {
	url := fmt.Sprintf("%s/v1/sites/%s/networks", c.BaseURL, c.SiteID)
	req, _ := http.NewRequest(http.MethodGet, url, nil)

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var response struct {
		Data []Network `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal networks: %w. response body: %s", err, string(body))
	}

	return response.Data, nil
}

// DNS Policies
type DNSPolicy struct {
	ID          string `json:"id,omitempty"`
	Type        string `json:"type"` // e.g., "A_RECORD", "AAAA_RECORD", "CNAME_RECORD", "MX_RECORD", "TXT_RECORD", "SRV_RECORD", "FORWARD_DOMAIN"
	Domain      string `json:"domain"`
	Enabled     bool   `json:"enabled"`
	IPv4Address string `json:"ipv4Address,omitempty"`
	IPv6Address string `json:"ipv6Address,omitempty"`
	CNAME       string `json:"cname,omitempty"`
	MXPriority  int    `json:"mxPriority,omitempty"`
	MXHostname  string `json:"mxHostname,omitempty"`
	TXTText     string `json:"txtText,omitempty"`
	SRVPriority int    `json:"srvPriority,omitempty"`
	SRVWeight   int    `json:"srvWeight,omitempty"`
	SRVPort     int    `json:"srvPort,omitempty"`
	Target      string `json:"target,omitempty"` // For FORWARD_DOMAIN
	TTL         int    `json:"ttlSeconds"`
}

func (c *Client) CreateDNSPolicy(policy DNSPolicy) (*DNSPolicy, error) {
	url := fmt.Sprintf("%s/v1/sites/%s/dns/policies", c.BaseURL, c.SiteID)

	// Debug logging to specific file
	debugFile := "/tmp/terraform-unifi-debug.log"
	f, _ := os.OpenFile(debugFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if f != nil {
		defer f.Close()
		f.WriteString(fmt.Sprintf("DEBUG: CreateDNSPolicy URL: %s\n", url))
		f.WriteString(fmt.Sprintf("DEBUG: Client SiteID: '%s'\n", c.SiteID))
		payload, _ := json.Marshal(policy)
		f.WriteString(fmt.Sprintf("DEBUG: Payload: %s\n", string(payload)))
	}

	payload, _ := json.Marshal(policy)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(payload))

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var result DNSPolicy
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) GetDNSPolicy(policyId string) (*DNSPolicy, error) {
	url := fmt.Sprintf("%s/v1/sites/%s/dns/policies/%s", c.BaseURL, c.SiteID, policyId)
	req, _ := http.NewRequest(http.MethodGet, url, nil)

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var result DNSPolicy
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) UpdateDNSPolicy(policyId string, policy DNSPolicy) (*DNSPolicy, error) {
	url := fmt.Sprintf("%s/v1/sites/%s/dns/policies/%s", c.BaseURL, c.SiteID, policyId)
	payload, _ := json.Marshal(policy)
	req, _ := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(payload))

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var result DNSPolicy
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) DeleteDNSPolicy(policyId string) error {
	url := fmt.Sprintf("%s/v1/sites/%s/dns/policies/%s", c.BaseURL, c.SiteID, policyId)
	req, _ := http.NewRequest(http.MethodDelete, url, nil)
	_, err := c.doRequest(req)
	return err
}
