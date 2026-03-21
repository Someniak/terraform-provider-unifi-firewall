package unifi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type authMode int

const (
	authModeAPIKey authMode = iota
	authModeCookie
)

// cacheEntry holds a cached API response with an expiration time.
type cacheEntry[T any] struct {
	data      T
	expiresAt time.Time
}

func (e *cacheEntry[T]) valid() bool {
	return time.Now().Before(e.expiresAt)
}

// cacheTTL controls how long list responses are cached. Within a single
// terraform plan/apply cycle this avoids redundant list calls when multiple
// data sources or resource reads need the same data.
const cacheTTL = 2 * time.Minute

type Client struct {
	BaseURL       string
	APIKey        string
	SiteID        string
	SiteReference string // e.g. "default" — used for legacy REST API paths
	Insecure      bool
	HTTPClient    *http.Client

	authMode  authMode
	csrfToken string

	mu             sync.Mutex
	sf             singleflight.Group
	zoneCache      *cacheEntry[[]FirewallZone]
	networkCache   *cacheEntry[[]Network]
	fwPolicyCache  *cacheEntry[[]FirewallPolicy]
	dnsPolicyCache *cacheEntry[[]DNSPolicy]
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

// NewClientWithCredentials creates a client that authenticates via legacy
// cookie-based login (POST /api/login). This is used for self-hosted UniFi
// Network Application instances that don't support API keys.
func NewClientWithCredentials(baseURL, username, password, siteID string, insecure bool) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}

	c := &Client{
		BaseURL:  baseURL,
		SiteID:   siteID,
		Insecure: insecure,
		authMode: authModeCookie,
		HTTPClient: &http.Client{
			Timeout:   time.Minute,
			Transport: tr,
			Jar:       jar,
		},
	}

	if err := c.login(username, password); err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	return c, nil
}

// networkBaseURL returns the Network Application base URL by stripping the
// "/integration" suffix from the integration API base URL. This is used for
// legacy REST API calls (e.g. /api/s/{site}/rest/user).
func (c *Client) networkBaseURL() string {
	return strings.TrimSuffix(c.BaseURL, "/integration")
}

func (c *Client) login(username, password string) error {
	loginURL := fmt.Sprintf("%s/api/login", c.networkBaseURL())
	payload, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})

	req, err := http.NewRequest(http.MethodPost, loginURL, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login returned status %d: %s", resp.StatusCode, string(body))
	}

	// Extract CSRF token from response header or cookie
	csrfToken := resp.Header.Get("X-CSRF-Token")
	if csrfToken == "" {
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "csrf_token" {
				csrfToken = cookie.Value
				break
			}
		}
	}
	c.csrfToken = csrfToken

	return nil
}

// InvalidateCache clears all cached data. Call after any mutation
// (create/update/delete) to ensure subsequent reads see fresh data.
func (c *Client) InvalidateCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.zoneCache = nil
	c.networkCache = nil
	c.fwPolicyCache = nil
	c.dnsPolicyCache = nil
}

// invalidateFWPolicyCache clears just the firewall policy cache.
func (c *Client) invalidateFWPolicyCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fwPolicyCache = nil
}

// invalidateDNSPolicyCache clears the DNS policy cache.
func (c *Client) invalidateDNSPolicyCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dnsPolicyCache = nil
}

func (c *Client) doRequest(req *http.Request) ([]byte, error) {
	req.Header.Set("Accept", "application/json")
	if req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	switch c.authMode {
	case authModeAPIKey:
		req.Header.Set("X-API-Key", c.APIKey)
	case authModeCookie:
		if c.csrfToken != "" {
			req.Header.Set("X-CSRF-Token", c.csrfToken)
		}
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
	url := fmt.Sprintf("%s/v1/sites?limit=200", c.BaseURL)
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
	c.mu.Lock()
	if c.zoneCache != nil && c.zoneCache.valid() {
		zones := c.zoneCache.data
		c.mu.Unlock()
		return zones, nil
	}
	c.mu.Unlock()

	v, err, _ := c.sf.Do("fw-zones", func() (interface{}, error) {
		var allZones []FirewallZone
		offset := 0
		const pageSize = 200

		for {
			url := fmt.Sprintf("%s/v1/sites/%s/firewall/zones?limit=%d&offset=%d", c.BaseURL, c.SiteID, pageSize, offset)
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

			allZones = append(allZones, response.Data...)
			if len(response.Data) < pageSize {
				break
			}
			offset += pageSize
		}

		c.mu.Lock()
		c.zoneCache = &cacheEntry[[]FirewallZone]{data: allZones, expiresAt: time.Now().Add(cacheTTL)}
		c.mu.Unlock()

		return allZones, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]FirewallZone), nil
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
	AllowReturnTraffic *bool  `json:"allowReturnTraffic,omitempty"`
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
	Mode         string   `json:"mode"`                   // EVERY_DAY, EVERY_WEEK, ONE_TIME_ONLY
	RepeatOnDays []string `json:"repeatOnDays,omitempty"`  // e.g. ["MONDAY","TUESDAY"] — EVERY_WEEK only
	Start        string   `json:"start,omitempty"`         // ONE_TIME_ONLY start datetime
	Stop         string   `json:"stop,omitempty"`          // ONE_TIME_ONLY stop datetime
}

// ListFirewallPolicies fetches all firewall policies, using a short-lived cache
// so that multiple resource reads within the same plan/apply share one API call.
func (c *Client) ListFirewallPolicies() ([]FirewallPolicy, error) {
	c.mu.Lock()
	if c.fwPolicyCache != nil && c.fwPolicyCache.valid() {
		policies := c.fwPolicyCache.data
		c.mu.Unlock()
		return policies, nil
	}
	c.mu.Unlock()

	v, err, _ := c.sf.Do("fw-policies", func() (interface{}, error) {
		var allPolicies []FirewallPolicy
		offset := 0
		const pageSize = 200

		for {
			url := fmt.Sprintf("%s/v1/sites/%s/firewall/policies?limit=%d&offset=%d", c.BaseURL, c.SiteID, pageSize, offset)
			req, _ := http.NewRequest(http.MethodGet, url, nil)

			body, err := c.doRequest(req)
			if err != nil {
				return nil, err
			}

			var response struct {
				Data []FirewallPolicy `json:"data"`
			}
			if err := json.Unmarshal(body, &response); err != nil {
				return nil, fmt.Errorf("failed to unmarshal firewall policies: %w. response body: %s", err, string(body))
			}

			allPolicies = append(allPolicies, response.Data...)
			if len(response.Data) < pageSize {
				break
			}
			offset += pageSize
		}

		c.mu.Lock()
		c.fwPolicyCache = &cacheEntry[[]FirewallPolicy]{data: allPolicies, expiresAt: time.Now().Add(cacheTTL)}
		c.mu.Unlock()

		return allPolicies, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]FirewallPolicy), nil
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

	c.invalidateFWPolicyCache()
	return &result, nil
}

// GetFirewallPolicy retrieves a single policy. It first checks the cached list
// of all policies (populated by ListFirewallPolicies) to avoid an extra API call.
// Falls back to a direct GET if the policy is not in cache.
func (c *Client) GetFirewallPolicy(policyId string) (*FirewallPolicy, error) {
	policies, err := c.ListFirewallPolicies()
	if err == nil {
		for i := range policies {
			if policies[i].ID == policyId {
				return &policies[i], nil
			}
		}
	}

	// Fallback: direct GET for a single policy (e.g. newly created, not yet in cache).
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

	c.invalidateFWPolicyCache()
	return &result, nil
}

func (c *Client) DeleteFirewallPolicy(policyId string) error {
	url := fmt.Sprintf("%s/v1/sites/%s/firewall/policies/%s", c.BaseURL, c.SiteID, policyId)
	req, _ := http.NewRequest(http.MethodDelete, url, nil)
	_, err := c.doRequest(req)
	c.invalidateFWPolicyCache()
	return err
}

// PatchFirewallPolicy partially updates a firewall policy (currently only loggingEnabled).
func (c *Client) PatchFirewallPolicy(policyId string, patch FirewallPolicyPatch) (*FirewallPolicy, error) {
	url := fmt.Sprintf("%s/v1/sites/%s/firewall/policies/%s", c.BaseURL, c.SiteID, policyId)
	payload, _ := json.Marshal(patch)
	req, _ := http.NewRequest(http.MethodPatch, url, bytes.NewBuffer(payload))

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var result FirewallPolicy
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	c.invalidateFWPolicyCache()
	return &result, nil
}

type FirewallPolicyPatch struct {
	LoggingEnabled *bool `json:"loggingEnabled,omitempty"`
}

// Firewall Policy Ordering
type FirewallPolicyOrdering struct {
	PolicyIDs []string `json:"policyIds"`
}

func (c *Client) GetFirewallPolicyOrdering() ([]string, error) {
	url := fmt.Sprintf("%s/v1/sites/%s/firewall/policies/ordering", c.BaseURL, c.SiteID)
	req, _ := http.NewRequest(http.MethodGet, url, nil)

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var result []string
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy ordering: %w. response body: %s", err, string(body))
	}

	return result, nil
}

func (c *Client) UpdateFirewallPolicyOrdering(ordering FirewallPolicyOrdering) ([]string, error) {
	url := fmt.Sprintf("%s/v1/sites/%s/firewall/policies/ordering", c.BaseURL, c.SiteID)
	payload, _ := json.Marshal(ordering)
	req, _ := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(payload))

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var result []string
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy ordering: %w. response body: %s", err, string(body))
	}

	c.invalidateFWPolicyCache()
	return result, nil
}

// Networks
type Network struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	VlanID     int    `json:"vlanId"`
	Management string `json:"management"`
}

func (c *Client) ListNetworks() ([]Network, error) {
	c.mu.Lock()
	if c.networkCache != nil && c.networkCache.valid() {
		networks := c.networkCache.data
		c.mu.Unlock()
		return networks, nil
	}
	c.mu.Unlock()

	v, err, _ := c.sf.Do("networks", func() (interface{}, error) {
		var allNetworks []Network
		offset := 0
		const pageSize = 200

		for {
			url := fmt.Sprintf("%s/v1/sites/%s/networks?limit=%d&offset=%d", c.BaseURL, c.SiteID, pageSize, offset)
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

			allNetworks = append(allNetworks, response.Data...)
			if len(response.Data) < pageSize {
				break
			}
			offset += pageSize
		}

		c.mu.Lock()
		c.networkCache = &cacheEntry[[]Network]{data: allNetworks, expiresAt: time.Now().Add(cacheTTL)}
		c.mu.Unlock()

		return allNetworks, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]Network), nil
}

// DNS Policies
type DNSPolicy struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"` // A_RECORD, AAAA_RECORD, CNAME_RECORD, MX_RECORD, TXT_RECORD, SRV_RECORD, FORWARD_DOMAIN
	Domain  string `json:"domain"`
	Enabled bool   `json:"enabled"`

	// A_RECORD
	IPv4Address string `json:"ipv4Address,omitempty"`
	// AAAA_RECORD
	IPv6Address string `json:"ipv6Address,omitempty"`
	// CNAME_RECORD
	TargetDomain string `json:"targetDomain,omitempty"`
	// MX_RECORD
	MailServerDomain string `json:"mailServerDomain,omitempty"`
	// MX_RECORD, SRV_RECORD (shared field name in API)
	Priority int `json:"priority,omitempty"`
	// SRV_RECORD
	ServerDomain string `json:"serverDomain,omitempty"`
	Service      string `json:"service,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	Weight       int    `json:"weight,omitempty"`
	Port         int    `json:"port,omitempty"`
	// TXT_RECORD
	Text string `json:"text,omitempty"`
	// FORWARD_DOMAIN
	IPAddress string `json:"ipAddress,omitempty"`
	// Common
	TTL int `json:"ttlSeconds"`
}

// ListDNSPolicies fetches all DNS policies for the given site, using a short-lived cache.
// The siteID parameter makes this safe for concurrent use without mutating Client state.
func (c *Client) ListDNSPolicies(siteID string) ([]DNSPolicy, error) {
	c.mu.Lock()
	if c.dnsPolicyCache != nil && c.dnsPolicyCache.valid() {
		policies := c.dnsPolicyCache.data
		c.mu.Unlock()
		return policies, nil
	}
	c.mu.Unlock()

	v, err, _ := c.sf.Do("dns-policies", func() (interface{}, error) {
		var allPolicies []DNSPolicy
		offset := 0
		const pageSize = 200

		for {
			url := fmt.Sprintf("%s/v1/sites/%s/dns/policies?limit=%d&offset=%d", c.BaseURL, siteID, pageSize, offset)
			req, _ := http.NewRequest(http.MethodGet, url, nil)

			body, err := c.doRequest(req)
			if err != nil {
				return nil, err
			}

			var response struct {
				Data []DNSPolicy `json:"data"`
			}
			if err := json.Unmarshal(body, &response); err != nil {
				return nil, fmt.Errorf("failed to unmarshal dns policies: %w. response body: %s", err, string(body))
			}

			allPolicies = append(allPolicies, response.Data...)
			if len(response.Data) < pageSize {
				break
			}
			offset += pageSize
		}

		c.mu.Lock()
		c.dnsPolicyCache = &cacheEntry[[]DNSPolicy]{data: allPolicies, expiresAt: time.Now().Add(cacheTTL)}
		c.mu.Unlock()

		return allPolicies, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]DNSPolicy), nil
}

func (c *Client) CreateDNSPolicy(siteID string, policy DNSPolicy) (*DNSPolicy, error) {
	url := fmt.Sprintf("%s/v1/sites/%s/dns/policies", c.BaseURL, siteID)
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

	c.invalidateDNSPolicyCache()
	return &result, nil
}

// GetDNSPolicy retrieves a single DNS policy. Uses the cached list when available.
// The siteID parameter makes this safe for concurrent use without mutating Client state.
func (c *Client) GetDNSPolicy(siteID, policyId string) (*DNSPolicy, error) {
	policies, err := c.ListDNSPolicies(siteID)
	if err == nil {
		for i := range policies {
			if policies[i].ID == policyId {
				return &policies[i], nil
			}
		}
	}

	// Fallback: direct GET.
	url := fmt.Sprintf("%s/v1/sites/%s/dns/policies/%s", c.BaseURL, siteID, policyId)
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

func (c *Client) UpdateDNSPolicy(siteID, policyId string, policy DNSPolicy) (*DNSPolicy, error) {
	url := fmt.Sprintf("%s/v1/sites/%s/dns/policies/%s", c.BaseURL, siteID, policyId)
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

	c.invalidateDNSPolicyCache()
	return &result, nil
}

func (c *Client) DeleteDNSPolicy(siteID, policyId string) error {
	url := fmt.Sprintf("%s/v1/sites/%s/dns/policies/%s", c.BaseURL, siteID, policyId)
	req, _ := http.NewRequest(http.MethodDelete, url, nil)
	_, err := c.doRequest(req)
	c.invalidateDNSPolicyCache()
	return err
}

// Client Devices (for fixed IP / DHCP reservations)
//
// Client operations use the legacy REST API (/api/s/{site}/rest/user) instead
// of the integration API. The REST API reads from MongoDB and sees all known
// clients (including offline and historical devices), whereas the integration
// API only tracks currently-connected clients.
type ClientDevice struct {
	ID         string `json:"_id,omitempty"`
	MAC        string `json:"mac,omitempty"`
	Name       string `json:"name,omitempty"`
	UseFixedIP bool   `json:"use_fixedip"`
	NetworkID  string `json:"network_id,omitempty"`
	FixedIP    string `json:"fixed_ip,omitempty"`
}

// restAPIResponse wraps the legacy REST API response format.
type restAPIResponse struct {
	Meta struct {
		RC  string `json:"rc"`
		Msg string `json:"msg,omitempty"`
	} `json:"meta"`
	Data json.RawMessage `json:"data"`
}

func (c *Client) restUserURL(objectID ...string) string {
	base := fmt.Sprintf("%s/api/s/%s/rest/user", c.networkBaseURL(), c.SiteReference)
	if len(objectID) > 0 && objectID[0] != "" {
		return base + "/" + objectID[0]
	}
	return base
}

func (c *Client) ListClients(_ string) ([]ClientDevice, error) {
	url := c.restUserURL()
	req, _ := http.NewRequest(http.MethodGet, url, nil)

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var resp restAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal clients: %w. response body: %s", err, string(body))
	}
	if resp.Meta.RC != "ok" {
		return nil, fmt.Errorf("REST API error: %s", resp.Meta.Msg)
	}

	var clients []ClientDevice
	if err := json.Unmarshal(resp.Data, &clients); err != nil {
		return nil, fmt.Errorf("failed to unmarshal client data: %w", err)
	}

	return clients, nil
}

func (c *Client) GetClient(_ string, clientID string) (*ClientDevice, error) {
	url := c.restUserURL(clientID)
	req, _ := http.NewRequest(http.MethodGet, url, nil)

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var resp restAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal client: %w. response body: %s", err, string(body))
	}
	if resp.Meta.RC != "ok" {
		return nil, fmt.Errorf("REST API error: %s", resp.Meta.Msg)
	}

	var clients []ClientDevice
	if err := json.Unmarshal(resp.Data, &clients); err != nil {
		return nil, fmt.Errorf("failed to unmarshal client data: %w", err)
	}
	if len(clients) == 0 {
		return nil, fmt.Errorf("client %q not found", clientID)
	}

	return &clients[0], nil
}

func (c *Client) SetClientFixedIP(_ string, clientID, networkID, fixedIP, name string) (*ClientDevice, error) {
	url := c.restUserURL(clientID)
	update := ClientDevice{
		UseFixedIP: true,
		NetworkID:  networkID,
		FixedIP:    fixedIP,
		Name:       name,
	}
	payload, _ := json.Marshal(update)
	req, _ := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(payload))

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var resp restAPIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	if resp.Meta.RC != "ok" {
		return nil, fmt.Errorf("REST API error: %s", resp.Meta.Msg)
	}

	var clients []ClientDevice
	if err := json.Unmarshal(resp.Data, &clients); err != nil {
		return nil, err
	}
	if len(clients) == 0 {
		return nil, fmt.Errorf("no client returned after update")
	}

	return &clients[0], nil
}

func (c *Client) UnsetClientFixedIP(_ string, clientID string) error {
	url := c.restUserURL(clientID)
	update := map[string]interface{}{
		"use_fixedip": false,
	}
	payload, _ := json.Marshal(update)
	req, _ := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(payload))

	_, err := c.doRequest(req)
	return err
}
