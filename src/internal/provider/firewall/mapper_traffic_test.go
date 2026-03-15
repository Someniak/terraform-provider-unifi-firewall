package firewall

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

func TestMapTrafficFilterToAPI_Nil(t *testing.T) {
	result := mapTrafficFilterToAPI(context.Background(), nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestMapTrafficFilterToAPI_PortFilter(t *testing.T) {
	ctx := context.Background()
	tf := &TrafficFilterModel{
		Type: types.StringValue("PORT"),
		PortFilter: &PortFilterModel{
			Type:          types.StringValue("PORTS"),
			MatchOpposite: types.BoolValue(false),
			Items: []PortItemModel{
				{Type: types.StringValue("PORT_NUMBER"), Value: types.Int32Value(80)},
				{Type: types.StringValue("PORT_NUMBER_RANGE"), Start: types.Int32Value(8000), Stop: types.Int32Value(9000)},
			},
		},
	}

	result := mapTrafficFilterToAPI(ctx, tf)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Type != "PORT" {
		t.Errorf("expected type PORT, got %q", result.Type)
	}
	if result.PortFilter == nil {
		t.Fatal("expected port filter")
	}
	if len(result.PortFilter.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(result.PortFilter.Items))
	}
	if result.PortFilter.Items[0].Value != 80 {
		t.Errorf("expected port 80, got %d", result.PortFilter.Items[0].Value)
	}
	if result.PortFilter.Items[1].Start != 8000 || result.PortFilter.Items[1].Stop != 9000 {
		t.Errorf("expected range 8000-9000, got %d-%d", result.PortFilter.Items[1].Start, result.PortFilter.Items[1].Stop)
	}
}

func TestMapTrafficFilterToAPI_IPAddressFilter(t *testing.T) {
	ctx := context.Background()
	items, _ := types.SetValueFrom(ctx, types.StringType, []string{"10.0.0.1", "192.168.1.0/24"})
	tf := &TrafficFilterModel{
		Type: types.StringValue("IP_ADDRESS"),
		IPAddressFilter: &IPAddressFilterModel{
			Type:          types.StringValue("IP_ADDRESSES"),
			MatchOpposite: types.BoolValue(true),
			Items:         items,
		},
	}

	result := mapTrafficFilterToAPI(ctx, tf)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.IPAddressFilter == nil {
		t.Fatal("expected IP address filter")
	}
	if !result.IPAddressFilter.MatchOpposite {
		t.Error("expected MatchOpposite=true")
	}
	if len(result.IPAddressFilter.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(result.IPAddressFilter.Items))
	}

	// Check IP vs SUBNET type detection
	typeMap := map[string]string{}
	for _, item := range result.IPAddressFilter.Items {
		typeMap[item.Value] = item.Type
	}
	if typeMap["10.0.0.1"] != "IP_ADDRESS" {
		t.Errorf("expected IP_ADDRESS for '10.0.0.1', got %q", typeMap["10.0.0.1"])
	}
	if typeMap["192.168.1.0/24"] != "SUBNET" {
		t.Errorf("expected SUBNET for '192.168.1.0/24', got %q", typeMap["192.168.1.0/24"])
	}
}

func TestMapTrafficFilterToAPI_MACAddress(t *testing.T) {
	ctx := context.Background()
	tf := &TrafficFilterModel{
		Type:       types.StringValue("MAC_ADDRESS"),
		MACAddress: types.StringValue("AA:BB:CC:DD:EE:FF"),
	}

	result := mapTrafficFilterToAPI(ctx, tf)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	macStr, ok := result.MACAddressFilter.(string)
	if !ok {
		t.Fatal("expected MACAddressFilter to be a string")
	}
	if macStr != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("expected 'AA:BB:CC:DD:EE:FF', got %q", macStr)
	}
}

func TestMapTrafficFilterToAPI_MACAddressFilter(t *testing.T) {
	ctx := context.Background()
	items, _ := types.SetValueFrom(ctx, types.StringType, []string{"11:22:33:44:55:66", "AA:BB:CC:DD:EE:FF"})
	tf := &TrafficFilterModel{
		Type: types.StringValue("MAC_ADDRESS"),
		MACAddressFilter: &MACAddressFilterModel{
			Type:          types.StringValue("MAC_ADDRESSES"),
			MatchOpposite: types.BoolValue(false),
			Items:         items,
		},
	}

	result := mapTrafficFilterToAPI(ctx, tf)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	macFilter, ok := result.MACAddressFilter.(*unifi.MACAddressFilter)
	if !ok {
		t.Fatalf("expected *MACAddressFilter, got %T", result.MACAddressFilter)
	}
	if len(macFilter.MACAddresses) != 2 {
		t.Errorf("expected 2 MACs, got %d", len(macFilter.MACAddresses))
	}
}

func TestMapTrafficFilterToAPI_NetworkFilter(t *testing.T) {
	ctx := context.Background()
	items, _ := types.SetValueFrom(ctx, types.StringType, []string{"net-1", "net-2"})
	tf := &TrafficFilterModel{
		Type: types.StringValue("NETWORK"),
		NetworkFilter: &NetworkFilterModel{
			MatchOpposite: types.BoolValue(true),
			Items:         items,
		},
	}

	result := mapTrafficFilterToAPI(ctx, tf)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.NetworkFilter == nil {
		t.Fatal("expected network filter")
	}
	if !result.NetworkFilter.MatchOpposite {
		t.Error("expected MatchOpposite=true")
	}
	if len(result.NetworkFilter.NetworkIDs) != 2 {
		t.Errorf("expected 2 network IDs, got %d", len(result.NetworkFilter.NetworkIDs))
	}
}

func TestMapTrafficFilterToAPI_DomainFilter(t *testing.T) {
	ctx := context.Background()
	items, _ := types.SetValueFrom(ctx, types.StringType, []string{"example.com", "test.org"})
	tf := &TrafficFilterModel{
		Type: types.StringValue("DOMAIN"),
		DomainFilter: &DomainFilterModel{
			Items: items,
		},
	}

	result := mapTrafficFilterToAPI(ctx, tf)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.DomainFilter == nil {
		t.Fatal("expected domain filter")
	}
	if result.DomainFilter.Type != "DOMAINS" {
		t.Errorf("expected type 'DOMAINS', got %q", result.DomainFilter.Type)
	}
	if len(result.DomainFilter.Domains) != 2 {
		t.Errorf("expected 2 domains, got %d", len(result.DomainFilter.Domains))
	}
}

// --- FromAPI tests ---

func TestMapTrafficFilterFromAPI_Nil(t *testing.T) {
	result := mapTrafficFilterFromAPI(context.Background(), nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestMapTrafficFilterFromAPI_PortFilter(t *testing.T) {
	ctx := context.Background()
	apiTF := &unifi.TrafficFilter{
		Type: "PORT",
		PortFilter: &unifi.PortFilter{
			Type:          "PORTS",
			MatchOpposite: false,
			Items: []unifi.PortItem{
				{Type: "PORT_NUMBER", Value: 443},
				{Type: "PORT_NUMBER_RANGE", Start: 1000, Stop: 2000},
			},
		},
	}

	result := mapTrafficFilterFromAPI(ctx, apiTF)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.PortFilter == nil {
		t.Fatal("expected port filter")
	}
	if len(result.PortFilter.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(result.PortFilter.Items))
	}
}

func TestMapTrafficFilterFromAPI_PortFilter_Sorting(t *testing.T) {
	ctx := context.Background()
	apiTF := &unifi.TrafficFilter{
		Type: "PORT",
		PortFilter: &unifi.PortFilter{
			Type: "PORTS",
			Items: []unifi.PortItem{
				{Type: "PORT_NUMBER", Value: 443},
				{Type: "PORT_NUMBER", Value: 80},
				{Type: "PORT_NUMBER", Value: 8080},
			},
		},
	}

	result := mapTrafficFilterFromAPI(ctx, apiTF)
	if result == nil || result.PortFilter == nil {
		t.Fatal("expected port filter")
	}

	items := result.PortFilter.Items
	if items[0].Value.ValueInt32() != 80 {
		t.Errorf("expected first item value 80, got %d", items[0].Value.ValueInt32())
	}
	if items[1].Value.ValueInt32() != 443 {
		t.Errorf("expected second item value 443, got %d", items[1].Value.ValueInt32())
	}
	if items[2].Value.ValueInt32() != 8080 {
		t.Errorf("expected third item value 8080, got %d", items[2].Value.ValueInt32())
	}
}

func TestMapTrafficFilterFromAPI_IPAddressFilter(t *testing.T) {
	ctx := context.Background()
	apiTF := &unifi.TrafficFilter{
		Type: "IP_ADDRESS",
		IPAddressFilter: &unifi.IPAddressFilter{
			Type:          "IP_ADDRESSES",
			MatchOpposite: true,
			Items: []unifi.IPAddressItem{
				{Type: "IP_ADDRESS", Value: "10.0.0.1"},
				{Type: "SUBNET", Value: "192.168.0.0/16"},
			},
		},
	}

	result := mapTrafficFilterFromAPI(ctx, apiTF)
	if result == nil || result.IPAddressFilter == nil {
		t.Fatal("expected IP address filter")
	}
	if !result.IPAddressFilter.MatchOpposite.ValueBool() {
		t.Error("expected MatchOpposite=true")
	}
}

func TestMapTrafficFilterFromAPI_MACAddress_String(t *testing.T) {
	ctx := context.Background()
	apiTF := &unifi.TrafficFilter{
		Type:             "MAC_ADDRESS",
		MACAddressFilter: "AA:BB:CC:DD:EE:FF",
	}

	result := mapTrafficFilterFromAPI(ctx, apiTF)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.MACAddress.ValueString() != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("expected 'AA:BB:CC:DD:EE:FF', got %q", result.MACAddress.ValueString())
	}
}

func TestMapTrafficFilterFromAPI_MACAddress_Struct(t *testing.T) {
	ctx := context.Background()
	apiTF := &unifi.TrafficFilter{
		Type: "MAC_ADDRESS",
		MACAddressFilter: &unifi.MACAddressFilter{
			MACAddresses: []string{"11:22:33:44:55:66"},
		},
	}

	result := mapTrafficFilterFromAPI(ctx, apiTF)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.MACAddressFilter == nil {
		t.Fatal("expected MACAddressFilter model")
	}
}

func TestMapTrafficFilterFromAPI_MACAddress_RawMap(t *testing.T) {
	ctx := context.Background()
	// Simulates raw JSON unmarshal where MACAddressFilter is a map
	apiTF := &unifi.TrafficFilter{
		Type: "MAC_ADDRESS",
		MACAddressFilter: map[string]interface{}{
			"macAddresses": []interface{}{"AA:BB:CC:DD:EE:FF"},
		},
	}

	result := mapTrafficFilterFromAPI(ctx, apiTF)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.MACAddressFilter == nil {
		t.Fatal("expected MACAddressFilter model from raw map")
	}
}

func TestMapTrafficFilterFromAPI_NetworkFilter(t *testing.T) {
	ctx := context.Background()
	apiTF := &unifi.TrafficFilter{
		Type: "NETWORK",
		NetworkFilter: &unifi.NetworkFilter{
			MatchOpposite: false,
			NetworkIDs:    []string{"net-1", "net-2"},
		},
	}

	result := mapTrafficFilterFromAPI(ctx, apiTF)
	if result == nil || result.NetworkFilter == nil {
		t.Fatal("expected network filter")
	}
	if result.NetworkFilter.Type.ValueString() != "NETWORK" {
		t.Errorf("expected type 'NETWORK', got %q", result.NetworkFilter.Type.ValueString())
	}
}

func TestMapTrafficFilterFromAPI_DomainFilter(t *testing.T) {
	ctx := context.Background()
	apiTF := &unifi.TrafficFilter{
		Type: "DOMAIN",
		DomainFilter: &unifi.DomainFilter{
			Type:    "DOMAINS",
			Domains: []string{"example.com"},
		},
	}

	result := mapTrafficFilterFromAPI(ctx, apiTF)
	if result == nil || result.DomainFilter == nil {
		t.Fatal("expected domain filter")
	}
}

func TestMapTrafficFilterFromAPI_EmptyFilter(t *testing.T) {
	ctx := context.Background()
	apiTF := &unifi.TrafficFilter{
		Type: "PORT",
		// All sub-filters are nil/empty
	}

	result := mapTrafficFilterFromAPI(ctx, apiTF)
	if result != nil {
		t.Error("expected nil for empty filter (hasContent=false)")
	}
}

func TestMapTrafficFilterRoundTrip_PortFilter(t *testing.T) {
	ctx := context.Background()
	original := &TrafficFilterModel{
		Type: types.StringValue("PORT"),
		PortFilter: &PortFilterModel{
			Type:          types.StringValue("PORTS"),
			MatchOpposite: types.BoolValue(false),
			Items: []PortItemModel{
				{Type: types.StringValue("PORT_NUMBER"), Value: types.Int32Value(80)},
				{Type: types.StringValue("PORT_NUMBER"), Value: types.Int32Value(443)},
			},
		},
	}

	apiTF := mapTrafficFilterToAPI(ctx, original)
	roundTripped := mapTrafficFilterFromAPI(ctx, apiTF)

	if roundTripped == nil || roundTripped.PortFilter == nil {
		t.Fatal("expected port filter after round trip")
	}
	if len(roundTripped.PortFilter.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(roundTripped.PortFilter.Items))
	}
	// Should be sorted: 80, 443
	if roundTripped.PortFilter.Items[0].Value.ValueInt32() != 80 {
		t.Errorf("expected first item 80, got %d", roundTripped.PortFilter.Items[0].Value.ValueInt32())
	}
	if roundTripped.PortFilter.Items[1].Value.ValueInt32() != 443 {
		t.Errorf("expected second item 443, got %d", roundTripped.PortFilter.Items[1].Value.ValueInt32())
	}
}
