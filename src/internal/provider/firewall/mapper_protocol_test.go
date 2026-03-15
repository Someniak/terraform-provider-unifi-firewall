package firewall

import "testing"

func TestMapProtocolToAPI(t *testing.T) {
	tests := []struct {
		name       string
		filterType string
		protocol   string
		key        string
		want       string
	}{
		{name: "named protocol", filterType: "NAMED_PROTOCOL", protocol: "TCP", key: "name", want: "TCP"},
		{name: "legacy protocol alias", filterType: "PROTOCOL", protocol: "UDP", key: "name", want: "UDP"},
		{name: "preset", filterType: "PRESET", protocol: "tcp_udp", key: "preset", want: "TCP_UDP"},
		{name: "protocol number", filterType: "PROTOCOL_NUMBER", protocol: "17", key: "number", want: "17"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapProtocolToAPI(tt.filterType, tt.protocol)
			if got[tt.key] != tt.want {
				t.Fatalf("expected %s=%s, got %#v", tt.key, tt.want, got)
			}
		})
	}
}

func TestMapProtocolToAPI_EmptyProtocol(t *testing.T) {
	got := mapProtocolToAPI("NAMED_PROTOCOL", "")
	if got != nil {
		t.Fatalf("expected nil for empty protocol, got %v", got)
	}
}

func TestNormalizeProtocolFilterType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"PROTOCOL", "NAMED_PROTOCOL"},
		{"protocol", "NAMED_PROTOCOL"},
		{"Protocol", "NAMED_PROTOCOL"},
		{"PRESET", "PRESET"},
		{"preset", "PRESET"},
		{"PROTOCOL_NUMBER", "PROTOCOL_NUMBER"},
		{"NAMED_PROTOCOL", "NAMED_PROTOCOL"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := normalizeProtocolFilterType(tt.input); got != tt.want {
				t.Errorf("normalizeProtocolFilterType(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMapProtocolFromAPI_Nil(t *testing.T) {
	if got := mapProtocolFromAPI(nil); got != "" {
		t.Errorf("expected empty string for nil, got %q", got)
	}
}

func TestMapProtocolFromAPI_EmptyMap(t *testing.T) {
	if got := mapProtocolFromAPI(map[string]interface{}{}); got != "" {
		t.Errorf("expected empty string for empty map, got %q", got)
	}
}

func TestMapProtocolFromAPI(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]interface{}
		want string
	}{
		{name: "name", in: map[string]interface{}{"name": "TCP"}, want: "tcp"},
		{name: "preset", in: map[string]interface{}{"preset": "TCP_UDP"}, want: "tcp_udp"},
		{name: "number string", in: map[string]interface{}{"number": "17"}, want: "17"},
		{name: "number numeric", in: map[string]interface{}{"number": float64(17)}, want: "17"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mapProtocolFromAPI(tt.in); got != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, got)
			}
		})
	}
}
