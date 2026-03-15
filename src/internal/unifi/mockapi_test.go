package unifi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// mockUnifiAPI is a stateful mock of the UniFi Network API for testing.
// It stores resources in memory and supports CRUD operations, error injection,
// and call counting.
type mockUnifiAPI struct {
	mu sync.Mutex

	sites      []Site
	zones      map[string][]FirewallZone   // keyed by siteID
	networks   map[string][]Network        // keyed by siteID
	fwPolicies map[string][]FirewallPolicy // keyed by siteID
	dnsPolicies map[string][]DNSPolicy      // keyed by siteID

	nextID int

	// callCounts tracks how many times each "METHOD /path" was hit.
	callCounts map[string]*atomic.Int32

	// errorOverrides forces a specific HTTP status for matching "METHOD /path-prefix".
	errorOverrides map[string]int
}

// newMockServer creates a mock API with sensible defaults and returns the
// httptest.Server and the mock for test assertions.
func newMockServer(t *testing.T) (*httptest.Server, *mockUnifiAPI) {
	t.Helper()
	m := &mockUnifiAPI{
		sites: []Site{
			{ID: "site-1", Name: "Default", InternalReference: "default"},
		},
		zones: map[string][]FirewallZone{
			"site-1": {
				{ID: "zone-lan", Name: "LAN", NetworkIDs: []string{"net-1"}},
				{ID: "zone-wan", Name: "WAN", NetworkIDs: []string{"net-2"}},
			},
		},
		networks: map[string][]Network{
			"site-1": {
				{ID: "net-1", Name: "Default", VlanID: 1, Management: "managed"},
				{ID: "net-2", Name: "Guest", VlanID: 100, Management: "managed"},
			},
		},
		fwPolicies:     map[string][]FirewallPolicy{},
		dnsPolicies:    map[string][]DNSPolicy{},
		callCounts:     map[string]*atomic.Int32{},
		errorOverrides: map[string]int{},
		nextID:         100,
	}

	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return srv, m
}

func (m *mockUnifiAPI) genID() string {
	m.nextID++
	return fmt.Sprintf("mock-%d", m.nextID)
}

func (m *mockUnifiAPI) trackCall(method, path string) {
	key := method + " " + path
	m.mu.Lock()
	if _, ok := m.callCounts[key]; !ok {
		m.callCounts[key] = &atomic.Int32{}
	}
	counter := m.callCounts[key]
	m.mu.Unlock()
	counter.Add(1)
}

// GetCallCount returns the number of times a specific "METHOD /path" was called.
func (m *mockUnifiAPI) GetCallCount(method, path string) int32 {
	key := method + " " + path
	m.mu.Lock()
	counter, ok := m.callCounts[key]
	m.mu.Unlock()
	if !ok {
		return 0
	}
	return counter.Load()
}

// SetError injects an error response for any request matching "METHOD /path-prefix".
func (m *mockUnifiAPI) SetError(method, pathPrefix string, statusCode int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorOverrides[method+" "+pathPrefix] = statusCode
}

// ClearError removes an error override.
func (m *mockUnifiAPI) ClearError(method, pathPrefix string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.errorOverrides, method+" "+pathPrefix)
}

// SetMalformedResponse makes the mock return invalid JSON for matching requests.
// Uses status 200 with garbage body to test unmarshal error paths.
func (m *mockUnifiAPI) SetMalformedResponse(method, pathPrefix string) {
	// We use a special status code 999 as a sentinel for malformed response.
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorOverrides[method+" "+pathPrefix] = 999
}

func (m *mockUnifiAPI) checkError(method, path string, w http.ResponseWriter) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, code := range m.errorOverrides {
		parts := strings.SplitN(key, " ", 2)
		if len(parts) == 2 && parts[0] == method && strings.HasPrefix(path, parts[1]) {
			if code == 999 {
				// Malformed response
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("not valid json{{{"))
				return true
			}
			w.WriteHeader(code)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("mock error %d", code)})
			return true
		}
	}
	return false
}

func (m *mockUnifiAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	method := r.Method
	m.trackCall(method, path)

	w.Header().Set("Content-Type", "application/json")

	if m.checkError(method, path, w) {
		return
	}

	// Route: GET /v1/sites
	if path == "/v1/sites" && method == http.MethodGet {
		m.mu.Lock()
		sites := m.sites
		m.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{"data": sites})
		return
	}

	// Parse /v1/sites/{siteId}/...
	parts := strings.Split(strings.TrimPrefix(path, "/v1/sites/"), "/")
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}
	siteID := parts[0]

	// Route: firewall zones
	if len(parts) == 3 && parts[1] == "firewall" && parts[2] == "zones" && method == http.MethodGet {
		m.mu.Lock()
		zones := m.zones[siteID]
		m.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{"data": zones})
		return
	}

	// Route: networks
	if len(parts) == 2 && parts[1] == "networks" && method == http.MethodGet {
		m.mu.Lock()
		networks := m.networks[siteID]
		m.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{"data": networks})
		return
	}

	// Route: firewall policies collection
	if len(parts) == 3 && parts[1] == "firewall" && parts[2] == "policies" {
		m.handleFWPolicies(w, r, siteID)
		return
	}

	// Route: firewall policies single item
	if len(parts) == 4 && parts[1] == "firewall" && parts[2] == "policies" {
		m.handleFWPolicy(w, r, siteID, parts[3])
		return
	}

	// Route: DNS policies collection
	if len(parts) == 3 && parts[1] == "dns" && parts[2] == "policies" {
		m.handleDNSPolicies(w, r, siteID)
		return
	}

	// Route: DNS policies single item
	if len(parts) == 4 && parts[1] == "dns" && parts[2] == "policies" {
		m.handleDNSPolicy(w, r, siteID, parts[3])
		return
	}

	http.NotFound(w, r)
}

func (m *mockUnifiAPI) handleFWPolicies(w http.ResponseWriter, r *http.Request, siteID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		policies := m.fwPolicies[siteID]
		if policies == nil {
			policies = []FirewallPolicy{}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"data": policies})
	case http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		var policy FirewallPolicy
		json.Unmarshal(body, &policy)
		policy.ID = m.genID()
		m.fwPolicies[siteID] = append(m.fwPolicies[siteID], policy)
		json.NewEncoder(w).Encode(policy)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *mockUnifiAPI) handleFWPolicy(w http.ResponseWriter, r *http.Request, siteID, policyID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	policies := m.fwPolicies[siteID]
	idx := -1
	for i, p := range policies {
		if p.ID == policyID {
			idx = i
			break
		}
	}

	switch r.Method {
	case http.MethodGet:
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		json.NewEncoder(w).Encode(policies[idx])
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		var policy FirewallPolicy
		json.Unmarshal(body, &policy)
		policy.ID = policyID
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		m.fwPolicies[siteID][idx] = policy
		json.NewEncoder(w).Encode(policy)
	case http.MethodDelete:
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		m.fwPolicies[siteID] = append(policies[:idx], policies[idx+1:]...)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *mockUnifiAPI) handleDNSPolicies(w http.ResponseWriter, r *http.Request, siteID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		policies := m.dnsPolicies[siteID]
		if policies == nil {
			policies = []DNSPolicy{}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"data": policies})
	case http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		var policy DNSPolicy
		json.Unmarshal(body, &policy)
		policy.ID = m.genID()
		m.dnsPolicies[siteID] = append(m.dnsPolicies[siteID], policy)
		json.NewEncoder(w).Encode(policy)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (m *mockUnifiAPI) handleDNSPolicy(w http.ResponseWriter, r *http.Request, siteID, policyID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	policies := m.dnsPolicies[siteID]
	idx := -1
	for i, p := range policies {
		if p.ID == policyID {
			idx = i
			break
		}
	}

	switch r.Method {
	case http.MethodGet:
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		json.NewEncoder(w).Encode(policies[idx])
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		var policy DNSPolicy
		json.Unmarshal(body, &policy)
		policy.ID = policyID
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		m.dnsPolicies[siteID][idx] = policy
		json.NewEncoder(w).Encode(policy)
	case http.MethodDelete:
		if idx == -1 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		m.dnsPolicies[siteID] = append(policies[:idx], policies[idx+1:]...)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
