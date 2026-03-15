package unifi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// newTestServer creates a test HTTP server that tracks call counts per path
// and returns configurable JSON responses.
func newTestServer(t *testing.T, responses map[string]interface{}) (*httptest.Server, map[string]*atomic.Int32) {
	t.Helper()
	counts := make(map[string]*atomic.Int32)
	for path := range responses {
		counts[path] = &atomic.Int32{}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		counter, ok := counts[path]
		if !ok {
			t.Logf("unexpected request path: %s", path)
			http.NotFound(w, r)
			return
		}
		counter.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(responses[path])
	}))
	return srv, counts
}

func TestListFirewallZones_CachesResponse(t *testing.T) {
	zones := []FirewallZone{
		{ID: "z1", Name: "LAN"},
		{ID: "z2", Name: "WAN"},
	}
	srv, counts := newTestServer(t, map[string]interface{}{
		"/v1/sites/site1/firewall/zones": map[string]interface{}{"data": zones},
	})
	defer srv.Close()

	client := NewClient(srv.URL, "key", "site1", false)

	// First call should hit the server.
	result1, err := client.ListFirewallZones()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result1) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(result1))
	}

	// Second call should use cache, not hit server again.
	result2, err := client.ListFirewallZones()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result2) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(result2))
	}

	callCount := counts["/v1/sites/site1/firewall/zones"].Load()
	if callCount != 1 {
		t.Errorf("expected 1 API call, got %d", callCount)
	}
}

func TestListNetworks_CachesResponse(t *testing.T) {
	networks := []Network{
		{ID: "n1", Name: "Default", VlanID: 1},
		{ID: "n2", Name: "Guest", VlanID: 100},
	}
	srv, counts := newTestServer(t, map[string]interface{}{
		"/v1/sites/site1/networks": map[string]interface{}{"data": networks},
	})
	defer srv.Close()

	client := NewClient(srv.URL, "key", "site1", false)

	for i := 0; i < 5; i++ {
		result, err := client.ListNetworks()
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if len(result) != 2 {
			t.Fatalf("call %d: expected 2 networks, got %d", i, len(result))
		}
	}

	callCount := counts["/v1/sites/site1/networks"].Load()
	if callCount != 1 {
		t.Errorf("expected 1 API call for 5 ListNetworks calls, got %d", callCount)
	}
}

func TestListFirewallPolicies_CachesResponse(t *testing.T) {
	policies := []FirewallPolicy{
		{ID: "p1", Name: "Allow SSH"},
		{ID: "p2", Name: "Block Telnet"},
	}
	srv, counts := newTestServer(t, map[string]interface{}{
		"/v1/sites/site1/firewall/policies": map[string]interface{}{"data": policies},
	})
	defer srv.Close()

	client := NewClient(srv.URL, "key", "site1", false)

	for i := 0; i < 3; i++ {
		result, err := client.ListFirewallPolicies()
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if len(result) != 2 {
			t.Fatalf("call %d: expected 2 policies, got %d", i, len(result))
		}
	}

	callCount := counts["/v1/sites/site1/firewall/policies"].Load()
	if callCount != 1 {
		t.Errorf("expected 1 API call for 3 ListFirewallPolicies calls, got %d", callCount)
	}
}

func TestGetFirewallPolicy_UsesCachedList(t *testing.T) {
	policies := []FirewallPolicy{
		{ID: "p1", Name: "Allow SSH"},
		{ID: "p2", Name: "Block Telnet"},
		{ID: "p3", Name: "Allow HTTP"},
	}
	srv, counts := newTestServer(t, map[string]interface{}{
		"/v1/sites/site1/firewall/policies": map[string]interface{}{"data": policies},
	})
	defer srv.Close()

	client := NewClient(srv.URL, "key", "site1", false)

	// Get three different policies — should only trigger 1 list call.
	for _, id := range []string{"p1", "p2", "p3"} {
		result, err := client.GetFirewallPolicy(id)
		if err != nil {
			t.Fatalf("GetFirewallPolicy(%s): unexpected error: %v", id, err)
		}
		if result.ID != id {
			t.Errorf("expected ID %s, got %s", id, result.ID)
		}
	}

	callCount := counts["/v1/sites/site1/firewall/policies"].Load()
	if callCount != 1 {
		t.Errorf("expected 1 API call for 3 GetFirewallPolicy calls, got %d", callCount)
	}
}

func TestGetDNSPolicy_UsesCachedList(t *testing.T) {
	policies := []DNSPolicy{
		{ID: "d1", Domain: "example.com", Type: "A_RECORD"},
		{ID: "d2", Domain: "test.com", Type: "CNAME_RECORD"},
	}
	srv, counts := newTestServer(t, map[string]interface{}{
		"/v1/sites/site1/dns/policies": map[string]interface{}{"data": policies},
	})
	defer srv.Close()

	client := NewClient(srv.URL, "key", "site1", false)

	for _, id := range []string{"d1", "d2"} {
		result, err := client.GetDNSPolicy("site1", id)
		if err != nil {
			t.Fatalf("GetDNSPolicy(%s): unexpected error: %v", id, err)
		}
		if result.ID != id {
			t.Errorf("expected ID %s, got %s", id, result.ID)
		}
	}

	callCount := counts["/v1/sites/site1/dns/policies"].Load()
	if callCount != 1 {
		t.Errorf("expected 1 API call for 2 GetDNSPolicy calls, got %d", callCount)
	}
}

func TestInvalidateCache_ClearsAllCaches(t *testing.T) {
	zones := []FirewallZone{{ID: "z1", Name: "LAN"}}
	networks := []Network{{ID: "n1", Name: "Default"}}
	srv, counts := newTestServer(t, map[string]interface{}{
		"/v1/sites/site1/firewall/zones": map[string]interface{}{"data": zones},
		"/v1/sites/site1/networks":       map[string]interface{}{"data": networks},
	})
	defer srv.Close()

	client := NewClient(srv.URL, "key", "site1", false)

	// Populate caches.
	client.ListFirewallZones()
	client.ListNetworks()

	// Invalidate and call again — should hit server again.
	client.InvalidateCache()
	client.ListFirewallZones()
	client.ListNetworks()

	zoneCount := counts["/v1/sites/site1/firewall/zones"].Load()
	netCount := counts["/v1/sites/site1/networks"].Load()
	if zoneCount != 2 {
		t.Errorf("expected 2 zone API calls after invalidation, got %d", zoneCount)
	}
	if netCount != 2 {
		t.Errorf("expected 2 network API calls after invalidation, got %d", netCount)
	}
}

func TestCacheExpiry(t *testing.T) {
	zones := []FirewallZone{{ID: "z1", Name: "LAN"}}
	srv, counts := newTestServer(t, map[string]interface{}{
		"/v1/sites/site1/firewall/zones": map[string]interface{}{"data": zones},
	})
	defer srv.Close()

	client := NewClient(srv.URL, "key", "site1", false)

	// Populate cache.
	client.ListFirewallZones()

	// Manually expire the cache.
	client.mu.Lock()
	client.zoneCache.expiresAt = time.Now().Add(-1 * time.Second)
	client.mu.Unlock()

	// Should refetch.
	client.ListFirewallZones()

	callCount := counts["/v1/sites/site1/firewall/zones"].Load()
	if callCount != 2 {
		t.Errorf("expected 2 API calls after cache expiry, got %d", callCount)
	}
}

func TestMutationInvalidatesCache(t *testing.T) {
	policies := []FirewallPolicy{{ID: "p1", Name: "Allow SSH"}}
	createdPolicy := FirewallPolicy{ID: "p-new", Name: "New Policy"}

	srv, counts := newTestServer(t, map[string]interface{}{
		"/v1/sites/site1/firewall/policies": map[string]interface{}{"data": policies},
	})
	defer srv.Close()

	// Override POST handler to return the created policy.
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if counter, ok := counts[path]; ok {
			counter.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			json.NewEncoder(w).Encode(createdPolicy)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"data": policies})
	})

	client := NewClient(srv.URL, "key", "site1", false)

	// Populate cache.
	client.ListFirewallPolicies()
	if counts["/v1/sites/site1/firewall/policies"].Load() != 1 {
		t.Fatal("expected 1 initial call")
	}

	// Create invalidates cache.
	client.CreateFirewallPolicy(FirewallPolicy{Name: "New Policy"})

	// Next list should refetch.
	client.ListFirewallPolicies()
	callCount := counts["/v1/sites/site1/firewall/policies"].Load()
	// 1 (initial list) + 1 (create POST) + 1 (refetch after invalidation) = 3
	if callCount != 3 {
		t.Errorf("expected 3 API calls (list + create + refetch), got %d", callCount)
	}
}
