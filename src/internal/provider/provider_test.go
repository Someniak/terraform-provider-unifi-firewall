package provider

import (
	"testing"

	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

func TestDiscoverSiteID_Auto_SingleSite(t *testing.T) {
	sites := []unifi.Site{
		{ID: "site-1", Name: "Default", InternalReference: "default"},
	}

	id, err := discoverSiteID(sites, "auto")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "site-1" {
		t.Errorf("expected 'site-1', got %q", id)
	}
}

func TestDiscoverSiteID_Auto_NoSites(t *testing.T) {
	sites := []unifi.Site{}

	_, err := discoverSiteID(sites, "auto")
	if err == nil {
		t.Fatal("expected error for no sites")
	}
	if got := err.Error(); !contains(got, "no sites") {
		t.Errorf("expected 'no sites' in error, got: %s", got)
	}
}

func TestDiscoverSiteID_Auto_MultipleSites(t *testing.T) {
	sites := []unifi.Site{
		{ID: "site-1", Name: "Site 1"},
		{ID: "site-2", Name: "Site 2"},
	}

	_, err := discoverSiteID(sites, "auto")
	if err == nil {
		t.Fatal("expected error for multiple sites")
	}
	if got := err.Error(); !contains(got, "multiple sites") {
		t.Errorf("expected 'multiple sites' in error, got: %s", got)
	}
}

func TestDiscoverSiteID_ByID(t *testing.T) {
	sites := []unifi.Site{
		{ID: "site-abc", Name: "Production", InternalReference: "prod"},
		{ID: "site-xyz", Name: "Staging", InternalReference: "staging"},
	}

	id, err := discoverSiteID(sites, "site-xyz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "site-xyz" {
		t.Errorf("expected 'site-xyz', got %q", id)
	}
}

func TestDiscoverSiteID_ByName(t *testing.T) {
	sites := []unifi.Site{
		{ID: "site-abc", Name: "Production", InternalReference: "prod"},
	}

	id, err := discoverSiteID(sites, "Production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "site-abc" {
		t.Errorf("expected 'site-abc', got %q", id)
	}
}

func TestDiscoverSiteID_ByInternalReference(t *testing.T) {
	sites := []unifi.Site{
		{ID: "site-abc", Name: "Production", InternalReference: "prod"},
	}

	id, err := discoverSiteID(sites, "prod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "site-abc" {
		t.Errorf("expected 'site-abc', got %q", id)
	}
}

func TestDiscoverSiteID_NotFound(t *testing.T) {
	sites := []unifi.Site{
		{ID: "site-1", Name: "Default", InternalReference: "default"},
	}

	_, err := discoverSiteID(sites, "nonexistent")
	if err == nil {
		t.Fatal("expected error for not found")
	}
	if got := err.Error(); !contains(got, "nonexistent") {
		t.Errorf("expected 'nonexistent' in error, got: %s", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
