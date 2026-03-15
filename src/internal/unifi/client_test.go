package unifi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- Sites ---

func TestListSites_HappyPath(t *testing.T) {
	srv, mock := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	sites, err := client.ListSites()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sites) != 1 {
		t.Fatalf("expected 1 site, got %d", len(sites))
	}
	if sites[0].ID != "site-1" {
		t.Errorf("expected site ID 'site-1', got %q", sites[0].ID)
	}
	if sites[0].Name != "Default" {
		t.Errorf("expected site name 'Default', got %q", sites[0].Name)
	}
	if sites[0].InternalReference != "default" {
		t.Errorf("expected internal reference 'default', got %q", sites[0].InternalReference)
	}
	if mock.GetCallCount("GET", "/v1/sites") != 1 {
		t.Errorf("expected 1 API call")
	}
}

func TestListSites_Empty(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.sites = []Site{}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)
	sites, err := client.ListSites()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sites) != 0 {
		t.Fatalf("expected 0 sites, got %d", len(sites))
	}
}

func TestListSites_ServerError(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.SetError("GET", "/v1/sites", 500)

	client := NewClient(srv.URL, "test-key", "site-1", false)
	_, err := client.ListSites()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); !contains(got, "500") {
		t.Errorf("expected error to contain '500', got: %s", got)
	}
}

func TestListSites_MalformedJSON(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.SetMalformedResponse("GET", "/v1/sites")

	client := NewClient(srv.URL, "test-key", "site-1", false)
	_, err := client.ListSites()
	if err == nil {
		t.Fatal("expected unmarshal error, got nil")
	}
	if got := err.Error(); !contains(got, "unmarshal") {
		t.Errorf("expected error to contain 'unmarshal', got: %s", got)
	}
}

// --- Firewall Zones ---

func TestListFirewallZones_HappyPath(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	zones, err := client.ListFirewallZones()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(zones) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(zones))
	}
	if zones[0].Name != "LAN" {
		t.Errorf("expected first zone 'LAN', got %q", zones[0].Name)
	}
	if len(zones[0].NetworkIDs) != 1 || zones[0].NetworkIDs[0] != "net-1" {
		t.Errorf("expected zone LAN to have network 'net-1'")
	}
}

func TestListFirewallZones_ServerError(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.SetError("GET", "/v1/sites/site-1/firewall/zones", 500)

	client := NewClient(srv.URL, "test-key", "site-1", false)
	_, err := client.ListFirewallZones()
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Verify cache was NOT populated — next call should try again.
	mock.ClearError("GET", "/v1/sites/site-1/firewall/zones")
	zones, err := client.ListFirewallZones()
	if err != nil {
		t.Fatalf("expected success after clearing error: %v", err)
	}
	if len(zones) != 2 {
		t.Errorf("expected 2 zones after retry, got %d", len(zones))
	}
}

// --- Networks ---

func TestListNetworks_HappyPath(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	networks, err := client.ListNetworks()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(networks) != 2 {
		t.Fatalf("expected 2 networks, got %d", len(networks))
	}
	if networks[0].Name != "Default" {
		t.Errorf("expected 'Default', got %q", networks[0].Name)
	}
	if networks[1].VlanID != 100 {
		t.Errorf("expected vlan 100, got %d", networks[1].VlanID)
	}
}

// --- Firewall Policies ---

func TestListFirewallPolicies_HappyPath(t *testing.T) {
	srv, mock := newMockServer(t)
	// Seed a policy
	mock.mu.Lock()
	mock.fwPolicies["site-1"] = []FirewallPolicy{
		{ID: "fw-1", Name: "Allow SSH", Enabled: true},
		{ID: "fw-2", Name: "Block Telnet", Enabled: false},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)
	policies, err := client.ListFirewallPolicies()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}
}

func TestCreateFirewallPolicy_HappyPath(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	policy := FirewallPolicy{
		Name:    "Allow HTTP",
		Enabled: true,
		Action:  FirewallAction{Type: "ALLOW"},
	}

	created, err := client.CreateFirewallPolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created.ID == "" {
		t.Error("expected server-generated ID, got empty")
	}
	if created.Name != "Allow HTTP" {
		t.Errorf("expected name 'Allow HTTP', got %q", created.Name)
	}
}

func TestCreateFirewallPolicy_ServerError(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.SetError("POST", "/v1/sites/site-1/firewall/policies", 400)

	client := NewClient(srv.URL, "test-key", "site-1", false)
	_, err := client.CreateFirewallPolicy(FirewallPolicy{Name: "Test"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !contains(err.Error(), "400") {
		t.Errorf("expected 400 in error, got: %s", err.Error())
	}
}

func TestGetFirewallPolicy_FromCache(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.fwPolicies["site-1"] = []FirewallPolicy{
		{ID: "fw-1", Name: "Allow SSH"},
		{ID: "fw-2", Name: "Block Telnet"},
		{ID: "fw-3", Name: "Allow HTTP"},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)

	// Get three policies — should only need 1 list call.
	for _, id := range []string{"fw-1", "fw-2", "fw-3"} {
		p, err := client.GetFirewallPolicy(id)
		if err != nil {
			t.Fatalf("GetFirewallPolicy(%s): %v", id, err)
		}
		if p.ID != id {
			t.Errorf("expected ID %s, got %s", id, p.ID)
		}
	}

	callCount := mock.GetCallCount("GET", "/v1/sites/site-1/firewall/policies")
	if callCount != 1 {
		t.Errorf("expected 1 list call for 3 gets, got %d", callCount)
	}
}

func TestGetFirewallPolicy_FallbackToDirectGET(t *testing.T) {
	srv, mock := newMockServer(t)
	// Start with empty list, but add the policy individually
	mock.mu.Lock()
	mock.fwPolicies["site-1"] = []FirewallPolicy{
		{ID: "fw-exist", Name: "Existing"},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)

	// Populate cache with empty-ish list
	client.ListFirewallPolicies()

	// Now add a policy that isn't in the cache
	mock.mu.Lock()
	mock.fwPolicies["site-1"] = append(mock.fwPolicies["site-1"],
		FirewallPolicy{ID: "fw-new", Name: "Newly Added"})
	mock.mu.Unlock()

	// Invalidate cache to force refetch
	client.invalidateFWPolicyCache()

	p, err := client.GetFirewallPolicy("fw-new")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name != "Newly Added" {
		t.Errorf("expected 'Newly Added', got %q", p.Name)
	}
}

func TestGetFirewallPolicy_NotFound(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	_, err := client.GetFirewallPolicy("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent policy, got nil")
	}
	if !contains(err.Error(), "404") {
		t.Errorf("expected 404 in error, got: %s", err.Error())
	}
}

func TestUpdateFirewallPolicy_HappyPath(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.fwPolicies["site-1"] = []FirewallPolicy{
		{ID: "fw-1", Name: "Old Name", Enabled: true},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)

	updated, err := client.UpdateFirewallPolicy("fw-1", FirewallPolicy{
		Name:    "New Name",
		Enabled: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.Name != "New Name" {
		t.Errorf("expected 'New Name', got %q", updated.Name)
	}
	if updated.ID != "fw-1" {
		t.Errorf("expected ID preserved as 'fw-1', got %q", updated.ID)
	}
}

func TestDeleteFirewallPolicy_HappyPath(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.fwPolicies["site-1"] = []FirewallPolicy{
		{ID: "fw-1", Name: "To Delete"},
		{ID: "fw-2", Name: "Keep"},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)

	err := client.DeleteFirewallPolicy("fw-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's gone
	client.InvalidateCache()
	policies, _ := client.ListFirewallPolicies()
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy remaining, got %d", len(policies))
	}
	if policies[0].ID != "fw-2" {
		t.Errorf("expected 'fw-2' remaining, got %q", policies[0].ID)
	}
}

func TestDeleteFirewallPolicy_NotFound(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	err := client.DeleteFirewallPolicy("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent policy, got nil")
	}
}

// --- DNS Policies ---

func TestListDNSPolicies_HappyPath(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.dnsPolicies["site-1"] = []DNSPolicy{
		{ID: "dns-1", Domain: "example.com", Type: "A_RECORD"},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)
	policies, err := client.ListDNSPolicies("site-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if policies[0].Domain != "example.com" {
		t.Errorf("expected 'example.com', got %q", policies[0].Domain)
	}
}

func TestCreateDNSPolicy_HappyPath(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	created, err := client.CreateDNSPolicy("site-1", DNSPolicy{
		Type:        "A_RECORD",
		Domain:      "test.com",
		Enabled:     true,
		IPv4Address: "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created.ID == "" {
		t.Error("expected server-generated ID")
	}
	if created.Domain != "test.com" {
		t.Errorf("expected 'test.com', got %q", created.Domain)
	}
}

func TestGetDNSPolicy_FromCache(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.dnsPolicies["site-1"] = []DNSPolicy{
		{ID: "dns-1", Domain: "a.com"},
		{ID: "dns-2", Domain: "b.com"},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)

	for _, id := range []string{"dns-1", "dns-2"} {
		p, err := client.GetDNSPolicy("site-1", id)
		if err != nil {
			t.Fatalf("GetDNSPolicy(%s): %v", id, err)
		}
		if p.ID != id {
			t.Errorf("expected %s, got %s", id, p.ID)
		}
	}

	callCount := mock.GetCallCount("GET", "/v1/sites/site-1/dns/policies")
	if callCount != 1 {
		t.Errorf("expected 1 list call for 2 gets, got %d", callCount)
	}
}

func TestGetDNSPolicy_FallbackToDirectGET(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.dnsPolicies["site-1"] = []DNSPolicy{
		{ID: "dns-1", Domain: "a.com"},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)

	// Populate cache, then add a new item
	client.ListDNSPolicies("site-1")
	mock.mu.Lock()
	mock.dnsPolicies["site-1"] = append(mock.dnsPolicies["site-1"],
		DNSPolicy{ID: "dns-new", Domain: "new.com"})
	mock.mu.Unlock()

	// Invalidate and get
	client.invalidateDNSPolicyCache()
	p, err := client.GetDNSPolicy("site-1", "dns-new")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Domain != "new.com" {
		t.Errorf("expected 'new.com', got %q", p.Domain)
	}
}

func TestUpdateDNSPolicy_HappyPath(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.dnsPolicies["site-1"] = []DNSPolicy{
		{ID: "dns-1", Domain: "old.com", Type: "A_RECORD"},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)

	updated, err := client.UpdateDNSPolicy("site-1", "dns-1", DNSPolicy{
		Domain: "new.com",
		Type:   "A_RECORD",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.Domain != "new.com" {
		t.Errorf("expected 'new.com', got %q", updated.Domain)
	}
}

func TestDeleteDNSPolicy_HappyPath(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.mu.Lock()
	mock.dnsPolicies["site-1"] = []DNSPolicy{
		{ID: "dns-1", Domain: "delete.com"},
	}
	mock.mu.Unlock()

	client := NewClient(srv.URL, "test-key", "site-1", false)
	err := client.DeleteDNSPolicy("site-1", "dns-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify gone
	client.InvalidateCache()
	policies, _ := client.ListDNSPolicies("site-1")
	if len(policies) != 0 {
		t.Errorf("expected 0 policies after delete, got %d", len(policies))
	}
}

// --- HTTP layer ---

func TestDoRequest_SetsHeaders(t *testing.T) {
	var capturedHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(200)
		w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(srv.Close)

	client := NewClient(srv.URL, "my-api-key", "site-1", false)
	client.ListSites()

	if got := capturedHeaders.Get("X-API-Key"); got != "my-api-key" {
		t.Errorf("expected X-API-Key 'my-api-key', got %q", got)
	}
	if got := capturedHeaders.Get("Accept"); got != "application/json" {
		t.Errorf("expected Accept 'application/json', got %q", got)
	}
}

func TestDoRequest_Unauthorized(t *testing.T) {
	srv, mock := newMockServer(t)
	mock.SetError("GET", "/v1/sites", 401)

	client := NewClient(srv.URL, "bad-key", "site-1", false)
	_, err := client.ListSites()
	if err == nil {
		t.Fatal("expected error for 401, got nil")
	}
	if !contains(err.Error(), "401") {
		t.Errorf("expected 401 in error, got: %s", err.Error())
	}
}

func TestDoRequest_NetworkError(t *testing.T) {
	// Create a server and immediately close it to simulate network error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	client := NewClient(srv.URL, "key", "site-1", false)
	_, err := client.ListSites()
	if err == nil {
		t.Fatal("expected network error, got nil")
	}
}

// --- Full CRUD integration ---

func TestFirewallPolicy_FullCRUDCycle(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	// Create
	created, err := client.CreateFirewallPolicy(FirewallPolicy{
		Name:    "Integration Test",
		Enabled: true,
		Action:  FirewallAction{Type: "ALLOW"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Read
	got, err := client.GetFirewallPolicy(created.ID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Name != "Integration Test" {
		t.Errorf("read: expected 'Integration Test', got %q", got.Name)
	}

	// Update
	updated, err := client.UpdateFirewallPolicy(created.ID, FirewallPolicy{
		Name:    "Updated Name",
		Enabled: false,
		Action:  FirewallAction{Type: "BLOCK"},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "Updated Name" {
		t.Errorf("update: expected 'Updated Name', got %q", updated.Name)
	}

	// Delete
	err = client.DeleteFirewallPolicy(created.ID)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Verify deleted
	client.InvalidateCache()
	_, err = client.GetFirewallPolicy(created.ID)
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
}

func TestDNSPolicy_FullCRUDCycle(t *testing.T) {
	srv, _ := newMockServer(t)
	client := NewClient(srv.URL, "test-key", "site-1", false)

	// Create
	created, err := client.CreateDNSPolicy("site-1", DNSPolicy{
		Type:        "A_RECORD",
		Domain:      "crud-test.com",
		Enabled:     true,
		IPv4Address: "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Read
	got, err := client.GetDNSPolicy("site-1", created.ID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Domain != "crud-test.com" {
		t.Errorf("expected 'crud-test.com', got %q", got.Domain)
	}

	// Update
	updated, err := client.UpdateDNSPolicy("site-1", created.ID, DNSPolicy{
		Type:   "A_RECORD",
		Domain: "updated.com",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Domain != "updated.com" {
		t.Errorf("expected 'updated.com', got %q", updated.Domain)
	}

	// Delete
	err = client.DeleteDNSPolicy("site-1", created.ID)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
}

// helper
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
