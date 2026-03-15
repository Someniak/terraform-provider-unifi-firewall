package firewall

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func minimalTFModel() FirewallPolicyResourceModel {
	return FirewallPolicyResourceModel{
		Enabled: types.BoolValue(true),
		Name:    types.StringValue("Test Policy"),
		Description: types.StringNull(),
		Action: &ActionModel{
			Type:               types.StringValue("ALLOW"),
			AllowReturnTraffic: types.BoolValue(true),
		},
		Source: &SourceDestModel{
			ZoneID: types.StringValue("zone-src"),
		},
		Destination: &SourceDestModel{
			ZoneID: types.StringValue("zone-dst"),
		},
		IPProtocolScope: &IPProtocolScopeModel{
			IPVersion: types.StringValue("IPV4"),
		},
		LoggingEnabled:        types.BoolValue(false),
		IPsecFilter:           types.StringNull(),
		ConnectionStateFilter: types.SetNull(types.StringType),
	}
}

func TestMapToAPI_MinimalPolicy(t *testing.T) {
	r := newTestResource()
	data := minimalTFModel()

	policy := r.mapToAPI(context.Background(), data)

	if policy.Name != "Test Policy" {
		t.Errorf("expected 'Test Policy', got %q", policy.Name)
	}
	if !policy.Enabled {
		t.Error("expected Enabled=true")
	}
	if policy.Action.Type != "ALLOW" {
		t.Errorf("expected action 'ALLOW', got %q", policy.Action.Type)
	}
	if policy.Source.ZoneID != "zone-src" {
		t.Errorf("expected source zone 'zone-src', got %q", policy.Source.ZoneID)
	}
	if policy.Destination.ZoneID != "zone-dst" {
		t.Errorf("expected dest zone 'zone-dst', got %q", policy.Destination.ZoneID)
	}
	if policy.IPProtocolScope.IPVersion != "IPV4" {
		t.Errorf("expected IPV4, got %q", policy.IPProtocolScope.IPVersion)
	}
}

func TestMapToAPI_WithDescription(t *testing.T) {
	r := newTestResource()
	data := minimalTFModel()
	data.Description = types.StringValue("My description")

	policy := r.mapToAPI(context.Background(), data)

	if policy.Description != "My description" {
		t.Errorf("expected 'My description', got %q", policy.Description)
	}
}

func TestMapToAPI_AllowReturnTraffic_AllowRule(t *testing.T) {
	r := newTestResource()
	data := minimalTFModel()
	data.Action.Type = types.StringValue("ALLOW")
	data.Action.AllowReturnTraffic = types.BoolValue(false)

	policy := r.mapToAPI(context.Background(), data)

	if policy.Action.AllowReturnTraffic == nil {
		t.Fatal("expected AllowReturnTraffic pointer set for ALLOW rule")
	}
	if *policy.Action.AllowReturnTraffic != false {
		t.Error("expected AllowReturnTraffic=false")
	}
}

func TestMapToAPI_AllowReturnTraffic_BlockRule(t *testing.T) {
	r := newTestResource()
	data := minimalTFModel()
	data.Action.Type = types.StringValue("BLOCK")
	data.Action.AllowReturnTraffic = types.BoolValue(true)

	policy := r.mapToAPI(context.Background(), data)

	// BLOCK rules should NOT get AllowReturnTraffic pointer
	if policy.Action.AllowReturnTraffic != nil {
		t.Error("expected nil AllowReturnTraffic for BLOCK rule")
	}
}

func TestMapToAPI_AllowReturnTraffic_Null(t *testing.T) {
	r := newTestResource()
	data := minimalTFModel()
	data.Action.AllowReturnTraffic = types.BoolNull()

	policy := r.mapToAPI(context.Background(), data)

	if policy.Action.AllowReturnTraffic != nil {
		t.Error("expected nil AllowReturnTraffic when null in model")
	}
}

func TestMapToAPI_IPsecFilter(t *testing.T) {
	r := newTestResource()
	data := minimalTFModel()
	data.IPsecFilter = types.StringValue("MATCH_IPSEC")

	policy := r.mapToAPI(context.Background(), data)

	if policy.IPsecFilter != "MATCH_IPSEC" {
		t.Errorf("expected 'MATCH_IPSEC', got %q", policy.IPsecFilter)
	}
}

func TestMapToAPI_Schedule_OneTimeOnly(t *testing.T) {
	r := newTestResource()
	data := minimalTFModel()
	data.Schedule = &FirewallScheduleModel{
		Mode:  types.StringValue("ONE_TIME_ONLY"),
		Start: types.StringValue("2025-01-01T00:00:00Z"),
		Stop:  types.StringValue("2025-01-02T00:00:00Z"),
	}

	policy := r.mapToAPI(context.Background(), data)

	if policy.Schedule == nil {
		t.Fatal("expected schedule")
	}
	if policy.Schedule.Mode != "ONE_TIME_ONLY" {
		t.Errorf("expected 'ONE_TIME_ONLY', got %q", policy.Schedule.Mode)
	}
}

func TestMapToAPI_Schedule_EveryDay(t *testing.T) {
	r := newTestResource()
	data := minimalTFModel()
	data.Schedule = &FirewallScheduleModel{
		Mode: types.StringValue("EVERY_DAY"),
		TimeRange: &TimeRangeModel{
			Start: types.StringValue("08:00"),
			Stop:  types.StringValue("17:00"),
		},
	}

	policy := r.mapToAPI(context.Background(), data)

	if policy.Schedule == nil {
		t.Fatal("expected schedule")
	}
	if policy.Schedule.Mode != "EVERY_DAY" {
		t.Errorf("expected 'EVERY_DAY', got %q", policy.Schedule.Mode)
	}
	if policy.Schedule.TimeFilter == nil {
		t.Fatal("expected TimeFilter")
	}
}

func TestMapToAPI_Schedule_EveryWeek(t *testing.T) {
	r := newTestResource()
	ctx := context.Background()
	data := minimalTFModel()
	daysSet, _ := types.SetValueFrom(ctx, types.StringType, []string{"MONDAY", "FRIDAY"})
	data.Schedule = &FirewallScheduleModel{
		Mode:       types.StringValue("EVERY_WEEK"),
		DaysOfWeek: daysSet,
		TimeRange: &TimeRangeModel{
			Start: types.StringValue("09:00"),
			Stop:  types.StringValue("18:00"),
		},
	}

	policy := r.mapToAPI(ctx, data)

	if policy.Schedule == nil {
		t.Fatal("expected schedule")
	}
	if policy.Schedule.Mode != "EVERY_WEEK" {
		t.Errorf("expected 'EVERY_WEEK', got %q", policy.Schedule.Mode)
	}
}

func TestMapToAPI_ConnectionStateFilter(t *testing.T) {
	r := newTestResource()
	ctx := context.Background()
	data := minimalTFModel()
	data.ConnectionStateFilter, _ = types.SetValueFrom(ctx, types.StringType, []string{"NEW", "ESTABLISHED"})

	policy := r.mapToAPI(ctx, data)

	if len(policy.ConnectionStateFilter) != 2 {
		t.Fatalf("expected 2 connection states, got %d", len(policy.ConnectionStateFilter))
	}
}

func TestMapToAPI_ProtocolFilter_Normalized(t *testing.T) {
	r := newTestResource()
	data := minimalTFModel()
	data.IPProtocolScope.ProtocolFilter = &ProtocolFilterModel{
		Type:          types.StringValue("PROTOCOL"),
		Protocol:      types.StringValue("TCP"),
		MatchOpposite: types.BoolValue(false),
	}

	policy := r.mapToAPI(context.Background(), data)

	if policy.IPProtocolScope.ProtocolFilter == nil {
		t.Fatal("expected protocol filter")
	}
	// "PROTOCOL" should be normalized to "NAMED_PROTOCOL"
	if policy.IPProtocolScope.ProtocolFilter.Type != "NAMED_PROTOCOL" {
		t.Errorf("expected 'NAMED_PROTOCOL', got %q", policy.IPProtocolScope.ProtocolFilter.Type)
	}
}

func TestMapToAPI_SourceTrafficFilter(t *testing.T) {
	r := newTestResource()
	ctx := context.Background()
	items, _ := types.SetValueFrom(ctx, types.StringType, []string{"example.com"})
	data := minimalTFModel()
	data.Source.TrafficFilter = &TrafficFilterModel{
		Type: types.StringValue("DOMAIN"),
		DomainFilter: &DomainFilterModel{
			Items: items,
		},
	}

	policy := r.mapToAPI(ctx, data)

	if policy.Source.TrafficFilter == nil {
		t.Fatal("expected source traffic filter")
	}
	if policy.Source.TrafficFilter.DomainFilter == nil {
		t.Fatal("expected domain filter")
	}
}

func TestMapToAPI_DestinationTrafficFilter(t *testing.T) {
	r := newTestResource()
	ctx := context.Background()
	data := minimalTFModel()
	data.Destination.TrafficFilter = &TrafficFilterModel{
		Type: types.StringValue("PORT"),
		PortFilter: &PortFilterModel{
			Type:          types.StringValue("PORTS"),
			MatchOpposite: types.BoolValue(false),
			Items: []PortItemModel{
				{Type: types.StringValue("PORT_NUMBER"), Value: types.Int32Value(443)},
			},
		},
	}

	policy := r.mapToAPI(ctx, data)

	if policy.Destination.TrafficFilter == nil {
		t.Fatal("expected destination traffic filter")
	}
	if policy.Destination.TrafficFilter.PortFilter == nil {
		t.Fatal("expected port filter")
	}
}
