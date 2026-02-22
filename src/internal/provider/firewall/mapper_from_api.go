package firewall

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

func (r *FirewallPolicyResource) mapFromAPI(ctx context.Context, p *unifi.FirewallPolicy, data *FirewallPolicyResourceModel) {
	data.ID = types.StringValue(p.ID)
	data.Enabled = types.BoolValue(p.Enabled)
	data.Name = types.StringValue(p.Name)
	if p.Description != "" {
		data.Description = types.StringValue(p.Description)
	} else {
		data.Description = types.StringNull()
	}
	actionType := p.Action.Type
	data.Action = &ActionModel{
		Type: types.StringValue(actionType),
	}
	if p.Action.AllowReturnTraffic != nil {
		data.Action.AllowReturnTraffic = types.BoolValue(*p.Action.AllowReturnTraffic)
	} else {
		// Default to true for ALLOW, false otherwise (BLOCK/REJECT)
		// Use case-insensitive comparison for stability
		isAllow := strings.EqualFold(actionType, "ALLOW")
		data.Action.AllowReturnTraffic = types.BoolValue(isAllow)
	}
	data.Source = &SourceDestModel{
		ZoneID: types.StringValue(p.Source.ZoneID),
	}
	data.Destination = &SourceDestModel{
		ZoneID: types.StringValue(p.Destination.ZoneID),
	}
	data.IPProtocolScope = &IPProtocolScopeModel{
		IPVersion: types.StringValue(p.IPProtocolScope.IPVersion),
	}
	data.LoggingEnabled = types.BoolValue(p.LoggingEnabled)
	if p.IPsecFilter != "" {
		data.IPsecFilter = types.StringValue(p.IPsecFilter)
	} else {
		data.IPsecFilter = types.StringNull()
	}

	if p.Schedule != nil {
		data.Schedule = &FirewallScheduleModel{
			Mode: types.StringValue(p.Schedule.Mode),
		}

		if tfMap, ok := p.Schedule.TimeFilter.(map[string]interface{}); ok {
			if start, ok := tfMap["start"].(string); ok {
				if p.Schedule.Mode == "ONE_TIME_ONLY" {
					data.Schedule.Start = types.StringValue(start)
				} else {
					if data.Schedule.TimeRange == nil {
						data.Schedule.TimeRange = &TimeRangeModel{}
					}
					data.Schedule.TimeRange.Start = types.StringValue(start)
				}
			}
			if stop, ok := tfMap["stop"].(string); ok {
				if p.Schedule.Mode == "ONE_TIME_ONLY" {
					data.Schedule.Stop = types.StringValue(stop)
				} else {
					if data.Schedule.TimeRange == nil {
						data.Schedule.TimeRange = &TimeRangeModel{}
					}
					data.Schedule.TimeRange.Stop = types.StringValue(stop)
				}
			}
			if days, ok := tfMap["days"].([]interface{}); ok {
				var daysStr []string
				for _, d := range days {
					if ds, ok := d.(string); ok {
						daysStr = append(daysStr, ds)
					}
				}
				data.Schedule.DaysOfWeek, _ = types.SetValueFrom(ctx, types.StringType, daysStr)
			}
			if tr, ok := tfMap["timeRange"].(map[string]interface{}); ok {
				if data.Schedule.TimeRange == nil {
					data.Schedule.TimeRange = &TimeRangeModel{}
				}
				if start, ok := tr["start"].(string); ok {
					data.Schedule.TimeRange.Start = types.StringValue(start)
				}
				if stop, ok := tr["stop"].(string); ok {
					data.Schedule.TimeRange.Stop = types.StringValue(stop)
				}
			}
		}
	}

	if len(p.ConnectionStateFilter) > 0 {
		data.ConnectionStateFilter, _ = types.SetValueFrom(ctx, types.StringType, p.ConnectionStateFilter)
	} else {
		data.ConnectionStateFilter = types.SetNull(types.StringType)
	}

	if p.Source.TrafficFilter != nil {
		data.Source.TrafficFilter = mapTrafficFilterFromAPI(ctx, p.Source.TrafficFilter)
	}

	if p.Destination.TrafficFilter != nil {
		data.Destination.TrafficFilter = mapTrafficFilterFromAPI(ctx, p.Destination.TrafficFilter)
	}

	if p.IPProtocolScope.ProtocolFilter != nil {
		data.IPProtocolScope.ProtocolFilter = &ProtocolFilterModel{
			Type:          types.StringValue(p.IPProtocolScope.ProtocolFilter.Type),
			MatchOpposite: types.BoolValue(p.IPProtocolScope.ProtocolFilter.MatchOpposite),
		}
		if protocol := mapProtocolFromAPI(p.IPProtocolScope.ProtocolFilter.Protocol); protocol != "" {
			data.IPProtocolScope.ProtocolFilter.Protocol = types.StringValue(protocol)
		}
	}
}
