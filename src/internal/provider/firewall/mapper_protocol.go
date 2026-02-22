package firewall

import (
	"fmt"
	"strings"
)

func mapProtocolToAPI(filterType, protocol string) map[string]interface{} {
	if protocol == "" {
		return nil
	}

	switch normalizeProtocolFilterType(filterType) {
	case "PRESET":
		return map[string]interface{}{"preset": strings.ToUpper(protocol)}
	case "PROTOCOL_NUMBER":
		return map[string]interface{}{"number": protocol}
	default:
		// Unifi API requires uppercase protocol names like "UDP" and "TCP"
		return map[string]interface{}{"name": strings.ToUpper(protocol)}
	}
}

func normalizeProtocolFilterType(filterType string) string {
	if strings.EqualFold(filterType, "PROTOCOL") {
		return "NAMED_PROTOCOL"
	}

	return strings.ToUpper(filterType)
}

func mapProtocolFromAPI(protocol map[string]interface{}) string {
	if protocol == nil {
		return ""
	}

	for _, key := range []string{"name", "preset", "number", "value"} {
		if value, ok := protocol[key].(string); ok && value != "" {
			return strings.ToLower(value)
		}
	}

	if number, ok := protocol["number"].(float64); ok {
		return fmt.Sprintf("%.0f", number)
	}

	return ""
}
