package firewall

import (
	"context"

	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

func (r *FirewallPolicyResource) mapToAPI(ctx context.Context, data FirewallPolicyResourceModel) unifi.FirewallPolicy {
	policy := unifi.FirewallPolicy{
		Enabled:     data.Enabled.ValueBool(),
		Name:        data.Name.ValueString(),
		Description: data.Description.ValueString(),
		Action: unifi.FirewallAction{
			Type: data.Action.Type.ValueString(),
		},
		Source: unifi.FirewallSourceDest{
			ZoneID: data.Source.ZoneID.ValueString(),
		},
		Destination: unifi.FirewallSourceDest{
			ZoneID: data.Destination.ZoneID.ValueString(),
		},
		IPProtocolScope: unifi.IPProtocolScope{
			IPVersion: data.IPProtocolScope.IPVersion.ValueString(),
		},
		LoggingEnabled: data.LoggingEnabled.ValueBool(),
	}

	if data.Action != nil && !data.Action.AllowReturnTraffic.IsNull() && !data.Action.AllowReturnTraffic.IsUnknown() {
		// UniFi API currently only supports allowReturnTraffic for ALLOW rules.
		actionType := data.Action.Type.ValueString()
		if actionType == "ALLOW" || actionType == "allow" {
			val := data.Action.AllowReturnTraffic.ValueBool()
			policy.Action.AllowReturnTraffic = &val
		}
	}

	if !data.IPsecFilter.IsNull() {
		policy.IPsecFilter = data.IPsecFilter.ValueString()
	}

	if data.Schedule != nil {
		policy.Schedule = &unifi.FirewallSchedule{
			Mode: data.Schedule.Mode.ValueString(),
		}

		mode := data.Schedule.Mode.ValueString()
		if mode == "ONE_TIME_ONLY" {
			policy.Schedule.TimeFilter = struct {
				Start string `json:"start,omitempty"`
				Stop  string `json:"stop,omitempty"`
			}{
				Start: data.Schedule.Start.ValueString(),
				Stop:  data.Schedule.Stop.ValueString(),
			}
		} else if mode == "EVERY_DAY" {
			if data.Schedule.TimeRange != nil {
				policy.Schedule.TimeFilter = struct {
					Start string `json:"start"`
					Stop  string `json:"stop"`
				}{
					Start: data.Schedule.TimeRange.Start.ValueString(),
					Stop:  data.Schedule.TimeRange.Stop.ValueString(),
				}
			}
		} else if mode == "EVERY_WEEK" {
			var days []string
			if !data.Schedule.DaysOfWeek.IsNull() {
				data.Schedule.DaysOfWeek.ElementsAs(ctx, &days, false)
			}
			tf := struct {
				Days      []string `json:"days"`
				TimeRange *struct {
					Start string `json:"start"`
					Stop  string `json:"stop"`
				} `json:"timeRange,omitempty"`
			}{
				Days: days,
			}
			if data.Schedule.TimeRange != nil {
				tf.TimeRange = &struct {
					Start string `json:"start"`
					Stop  string `json:"stop"`
				}{
					Start: data.Schedule.TimeRange.Start.ValueString(),
					Stop:  data.Schedule.TimeRange.Stop.ValueString(),
				}
			}
			policy.Schedule.TimeFilter = tf
		}
	}

	if !data.ConnectionStateFilter.IsNull() {
		var states []string
		data.ConnectionStateFilter.ElementsAs(ctx, &states, false)
		policy.ConnectionStateFilter = states
	}

	if data.Source != nil {
		policy.Source.TrafficFilter = mapTrafficFilterToAPI(ctx, data.Source.TrafficFilter)
	}

	if data.Destination != nil {
		policy.Destination.TrafficFilter = mapTrafficFilterToAPI(ctx, data.Destination.TrafficFilter)
	}

	if data.IPProtocolScope != nil && data.IPProtocolScope.ProtocolFilter != nil {
		policy.IPProtocolScope.ProtocolFilter = &unifi.ProtocolFilter{
			Type:          normalizeProtocolFilterType(data.IPProtocolScope.ProtocolFilter.Type.ValueString()),
			MatchOpposite: data.IPProtocolScope.ProtocolFilter.MatchOpposite.ValueBool(),
		}
		if !data.IPProtocolScope.ProtocolFilter.Protocol.IsNull() {
			policy.IPProtocolScope.ProtocolFilter.Protocol = mapProtocolToAPI(
				data.IPProtocolScope.ProtocolFilter.Type.ValueString(),
				data.IPProtocolScope.ProtocolFilter.Protocol.ValueString(),
			)
		}
	}

	return policy
}
