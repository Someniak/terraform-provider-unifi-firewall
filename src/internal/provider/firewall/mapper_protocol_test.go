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
		{name: "named protocol", filterType: "NAMED_PROTOCOL", protocol: "TCP", key: "name", want: "tcp"},
		{name: "legacy protocol alias", filterType: "PROTOCOL", protocol: "UDP", key: "name", want: "udp"},
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

func TestMapProtocolFromAPI(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]interface{}
		want string
	}{
		{name: "name", in: map[string]interface{}{"name": "tcp"}, want: "tcp"},
		{name: "preset", in: map[string]interface{}{"preset": "TCP_UDP"}, want: "TCP_UDP"},
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
