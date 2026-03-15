package firewall

import (
	"context"
	"testing"

	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

func newTestResource() *FirewallPolicyResource {
	return &FirewallPolicyResource{}
}

func minimalAPIPolicy() *unifi.FirewallPolicy {
	return &unifi.FirewallPolicy{
		ID:      "test-id",
		Enabled: true,
		Name:    "Test Policy",
		Action:  unifi.FirewallAction{Type: "ALLOW"},
		Source:  unifi.FirewallSourceDest{ZoneID: "zone-src"},
		Destination: unifi.FirewallSourceDest{ZoneID: "zone-dst"},
		IPProtocolScope: unifi.IPProtocolScope{IPVersion: "IPV4"},
	}
}

func TestMapFromAPI_MinimalPolicy(t *testing.T) {
	r := newTestResource()
	p := minimalAPIPolicy()
	var data FirewallPolicyResourceModel

	r.mapFromAPI(context.Background(), p, &data)

	if data.ID.ValueString() != "test-id" {
		t.Errorf("expected ID 'test-id', got %q", data.ID.ValueString())
	}
	if !data.Enabled.ValueBool() {
		t.Error("expected Enabled=true")
	}
	if data.Name.ValueString() != "Test Policy" {
		t.Errorf("expected name 'Test Policy', got %q", data.Name.ValueString())
	}
	if !data.Description.IsNull() {
		t.Error("expected null description for empty string")
	}
	if !data.IPsecFilter.IsNull() {
		t.Error("expected null ipsec_filter for empty string")
	}
	if data.Schedule != nil {
		t.Error("expected nil schedule")
	}
	if !data.ConnectionStateFilter.IsNull() {
		t.Error("expected null connection_state_filter for empty slice")
	}
}

func TestMapFromAPI_WithDescription(t *testing.T) {
	r := newTestResource()
	p := minimalAPIPolicy()
	p.Description = "A test policy"
	var data FirewallPolicyResourceModel

	r.mapFromAPI(context.Background(), p, &data)

	if data.Description.ValueString() != "A test policy" {
		t.Errorf("expected description 'A test policy', got %q", data.Description.ValueString())
	}
}

func TestMapFromAPI_AllowReturnTraffic_Explicit(t *testing.T) {
	r := newTestResource()
	p := minimalAPIPolicy()
	val := false
	p.Action.AllowReturnTraffic = &val
	var data FirewallPolicyResourceModel

	r.mapFromAPI(context.Background(), p, &data)

	if data.Action.AllowReturnTraffic.ValueBool() != false {
		t.Error("expected AllowReturnTraffic=false when explicitly set")
	}
}

func TestMapFromAPI_AllowReturnTraffic_DefaultAllow(t *testing.T) {
	r := newTestResource()
	p := minimalAPIPolicy()
	p.Action.Type = "ALLOW"
	p.Action.AllowReturnTraffic = nil
	var data FirewallPolicyResourceModel

	r.mapFromAPI(context.Background(), p, &data)

	if !data.Action.AllowReturnTraffic.ValueBool() {
		t.Error("expected AllowReturnTraffic=true default for ALLOW action")
	}
}

func TestMapFromAPI_AllowReturnTraffic_DefaultBlock(t *testing.T) {
	r := newTestResource()
	p := minimalAPIPolicy()
	p.Action.Type = "BLOCK"
	p.Action.AllowReturnTraffic = nil
	var data FirewallPolicyResourceModel

	r.mapFromAPI(context.Background(), p, &data)

	if data.Action.AllowReturnTraffic.ValueBool() {
		t.Error("expected AllowReturnTraffic=false default for BLOCK action")
	}
}

func TestMapFromAPI_AllowReturnTraffic_CaseInsensitive(t *testing.T) {
	r := newTestResource()
	p := minimalAPIPolicy()
	p.Action.Type = "allow"
	p.Action.AllowReturnTraffic = nil
	var data FirewallPolicyResourceModel

	r.mapFromAPI(context.Background(), p, &data)

	if !data.Action.AllowReturnTraffic.ValueBool() {
		t.Error("expected AllowReturnTraffic=true for lowercase 'allow'")
	}
}

func TestMapFromAPI_IPsecFilter(t *testing.T) {
	r := newTestResource()
	p := minimalAPIPolicy()
	p.IPsecFilter = "MATCH_IPSEC"
	var data FirewallPolicyResourceModel

	r.mapFromAPI(context.Background(), p, &data)

	if data.IPsecFilter.ValueString() != "MATCH_IPSEC" {
		t.Errorf("expected 'MATCH_IPSEC', got %q", data.IPsecFilter.ValueString())
	}
}

func TestMapFromAPI_Schedule_OneTimeOnly(t *testing.T) {
	r := newTestResource()
	p := minimalAPIPolicy()
	p.Schedule = &unifi.FirewallSchedule{
		Mode: "ONE_TIME_ONLY",
		TimeFilter: map[string]interface{}{
			"start": "2025-01-01T00:00:00Z",
			"stop":  "2025-01-02T00:00:00Z",
		},
	}
	var data FirewallPolicyResourceModel

	r.mapFromAPI(context.Background(), p, &data)

	if data.Schedule == nil {
		t.Fatal("expected schedule")
	}
	if data.Schedule.Mode.ValueString() != "ONE_TIME_ONLY" {
		t.Errorf("expected mode 'ONE_TIME_ONLY', got %q", data.Schedule.Mode.ValueString())
	}
	if data.Schedule.Start.ValueString() != "2025-01-01T00:00:00Z" {
		t.Errorf("expected start '2025-01-01T00:00:00Z', got %q", data.Schedule.Start.ValueString())
	}
	if data.Schedule.Stop.ValueString() != "2025-01-02T00:00:00Z" {
		t.Errorf("expected stop '2025-01-02T00:00:00Z', got %q", data.Schedule.Stop.ValueString())
	}
	// ONE_TIME_ONLY should NOT set TimeRange
	if data.Schedule.TimeRange != nil {
		t.Error("expected nil TimeRange for ONE_TIME_ONLY")
	}
}

func TestMapFromAPI_Schedule_EveryDay(t *testing.T) {
	r := newTestResource()
	p := minimalAPIPolicy()
	p.Schedule = &unifi.FirewallSchedule{
		Mode: "EVERY_DAY",
		TimeFilter: map[string]interface{}{
			"start": "08:00",
			"stop":  "17:00",
		},
	}
	var data FirewallPolicyResourceModel

	r.mapFromAPI(context.Background(), p, &data)

	if data.Schedule == nil {
		t.Fatal("expected schedule")
	}
	if data.Schedule.TimeRange == nil {
		t.Fatal("expected TimeRange for EVERY_DAY")
	}
	if data.Schedule.TimeRange.Start.ValueString() != "08:00" {
		t.Errorf("expected '08:00', got %q", data.Schedule.TimeRange.Start.ValueString())
	}
	if data.Schedule.TimeRange.Stop.ValueString() != "17:00" {
		t.Errorf("expected '17:00', got %q", data.Schedule.TimeRange.Stop.ValueString())
	}
}

func TestMapFromAPI_Schedule_EveryWeek(t *testing.T) {
	r := newTestResource()
	p := minimalAPIPolicy()
	p.Schedule = &unifi.FirewallSchedule{
		Mode: "EVERY_WEEK",
		TimeFilter: map[string]interface{}{
			"days": []interface{}{"MONDAY", "FRIDAY"},
			"timeRange": map[string]interface{}{
				"start": "09:00",
				"stop":  "18:00",
			},
		},
	}
	var data FirewallPolicyResourceModel

	r.mapFromAPI(context.Background(), p, &data)

	if data.Schedule == nil {
		t.Fatal("expected schedule")
	}
	if data.Schedule.DaysOfWeek.IsNull() {
		t.Fatal("expected non-null DaysOfWeek")
	}
	var days []string
	data.Schedule.DaysOfWeek.ElementsAs(context.Background(), &days, false)
	if len(days) != 2 {
		t.Errorf("expected 2 days, got %d", len(days))
	}
	if data.Schedule.TimeRange == nil {
		t.Fatal("expected TimeRange for EVERY_WEEK")
	}
	if data.Schedule.TimeRange.Start.ValueString() != "09:00" {
		t.Errorf("expected '09:00', got %q", data.Schedule.TimeRange.Start.ValueString())
	}
}

func TestMapFromAPI_ConnectionStateFilter(t *testing.T) {
	r := newTestResource()
	p := minimalAPIPolicy()
	p.ConnectionStateFilter = []string{"NEW", "ESTABLISHED"}
	var data FirewallPolicyResourceModel

	r.mapFromAPI(context.Background(), p, &data)

	if data.ConnectionStateFilter.IsNull() {
		t.Fatal("expected non-null ConnectionStateFilter")
	}
	var states []string
	data.ConnectionStateFilter.ElementsAs(context.Background(), &states, false)
	if len(states) != 2 {
		t.Errorf("expected 2 states, got %d", len(states))
	}
}

func TestMapFromAPI_ProtocolFilter_NamedProtocol(t *testing.T) {
	r := newTestResource()
	p := minimalAPIPolicy()
	p.IPProtocolScope.ProtocolFilter = &unifi.ProtocolFilter{
		Type:          "NAMED_PROTOCOL",
		MatchOpposite: false,
		Protocol:      map[string]interface{}{"name": "TCP"},
	}
	var data FirewallPolicyResourceModel

	r.mapFromAPI(context.Background(), p, &data)

	if data.IPProtocolScope.ProtocolFilter == nil {
		t.Fatal("expected protocol filter")
	}
	// NAMED_PROTOCOL should be reverse-mapped to "PROTOCOL"
	if data.IPProtocolScope.ProtocolFilter.Type.ValueString() != "PROTOCOL" {
		t.Errorf("expected type 'PROTOCOL' (reverse mapped), got %q", data.IPProtocolScope.ProtocolFilter.Type.ValueString())
	}
	if data.IPProtocolScope.ProtocolFilter.Protocol.ValueString() != "tcp" {
		t.Errorf("expected protocol 'tcp', got %q", data.IPProtocolScope.ProtocolFilter.Protocol.ValueString())
	}
}

func TestMapFromAPI_LoggingEnabled(t *testing.T) {
	r := newTestResource()
	p := minimalAPIPolicy()
	p.LoggingEnabled = true
	var data FirewallPolicyResourceModel

	r.mapFromAPI(context.Background(), p, &data)

	if !data.LoggingEnabled.ValueBool() {
		t.Error("expected LoggingEnabled=true")
	}
}

func TestMapFromAPI_SourceTrafficFilter(t *testing.T) {
	r := newTestResource()
	p := minimalAPIPolicy()
	p.Source.TrafficFilter = &unifi.TrafficFilter{
		Type: "PORT",
		PortFilter: &unifi.PortFilter{
			Type:  "PORTS",
			Items: []unifi.PortItem{{Type: "PORT_NUMBER", Value: 22}},
		},
	}
	var data FirewallPolicyResourceModel

	r.mapFromAPI(context.Background(), p, &data)

	if data.Source.TrafficFilter == nil {
		t.Fatal("expected source traffic filter")
	}
	if data.Source.TrafficFilter.PortFilter == nil {
		t.Fatal("expected port filter on source")
	}
}

func TestMapFromAPI_DestinationTrafficFilter(t *testing.T) {
	r := newTestResource()
	p := minimalAPIPolicy()
	p.Destination.TrafficFilter = &unifi.TrafficFilter{
		Type: "DOMAIN",
		DomainFilter: &unifi.DomainFilter{
			Type:    "DOMAINS",
			Domains: []string{"example.com"},
		},
	}
	var data FirewallPolicyResourceModel

	r.mapFromAPI(context.Background(), p, &data)

	if data.Destination.TrafficFilter == nil {
		t.Fatal("expected destination traffic filter")
	}
	if data.Destination.TrafficFilter.DomainFilter == nil {
		t.Fatal("expected domain filter on destination")
	}
}

func TestMapFromAPI_ActionType(t *testing.T) {
	tests := []struct {
		actionType string
	}{
		{"ALLOW"},
		{"BLOCK"},
		{"REJECT"},
	}

	for _, tt := range tests {
		t.Run(tt.actionType, func(t *testing.T) {
			r := newTestResource()
			p := minimalAPIPolicy()
			p.Action.Type = tt.actionType
			var data FirewallPolicyResourceModel
			r.mapFromAPI(context.Background(), p, &data)

			if data.Action.Type.ValueString() != tt.actionType {
				t.Errorf("expected %q, got %q", tt.actionType, data.Action.Type.ValueString())
			}
		})
	}
}
