package firewall

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type FirewallPolicyResourceModel struct {
	ID                    types.String           `tfsdk:"id"`
	Enabled               types.Bool             `tfsdk:"enabled"`
	Name                  types.String           `tfsdk:"name"`
	Description           types.String           `tfsdk:"description"`
	Action                *ActionModel           `tfsdk:"action"`
	Source                *SourceDestModel       `tfsdk:"source"`
	Destination           *SourceDestModel       `tfsdk:"destination"`
	IPProtocolScope       *IPProtocolScopeModel  `tfsdk:"ip_protocol_scope"`
	ConnectionStateFilter types.Set              `tfsdk:"connection_state_filter"`
	LoggingEnabled        types.Bool             `tfsdk:"logging_enabled"`
	IPsecFilter           types.String           `tfsdk:"ipsec_filter"`
	Schedule              *FirewallScheduleModel `tfsdk:"schedule"`
}

type FirewallScheduleModel struct {
	Mode       types.String    `tfsdk:"mode"`
	TimeRange  *TimeRangeModel `tfsdk:"time_range"`
	DaysOfWeek types.Set       `tfsdk:"days_of_week"`
	Start      types.String    `tfsdk:"start"`
	Stop       types.String    `tfsdk:"stop"`
}

type TimeRangeModel struct {
	Start types.String `tfsdk:"start"`
	Stop  types.String `tfsdk:"stop"`
}

type ActionModel struct {
	Type               types.String `tfsdk:"type"`
	AllowReturnTraffic types.Bool   `tfsdk:"allow_return_traffic"`
}

type SourceDestModel struct {
	ZoneID        types.String        `tfsdk:"zone_id"`
	TrafficFilter *TrafficFilterModel `tfsdk:"traffic_filter"`
}

type TrafficFilterModel struct {
	Type             types.String           `tfsdk:"type"`
	PortFilter       *PortFilterModel       `tfsdk:"port_filter"`
	DomainFilter     *DomainFilterModel     `tfsdk:"domain_filter"`
	IPAddressFilter  *IPAddressFilterModel  `tfsdk:"ip_address_filter"`
	MACAddressFilter *MACAddressFilterModel `tfsdk:"mac_address_filter"`
	NetworkFilter    *NetworkFilterModel    `tfsdk:"network_filter"`
	MACAddress       types.String           `tfsdk:"mac_address"`
}

type IPAddressFilterModel struct {
	Type          types.String `tfsdk:"type"`
	MatchOpposite types.Bool   `tfsdk:"match_opposite"`
	Items         types.Set    `tfsdk:"items"`
}

type MACAddressFilterModel struct {
	Type          types.String `tfsdk:"type"`
	MatchOpposite types.Bool   `tfsdk:"match_opposite"`
	Items         types.Set    `tfsdk:"items"`
}

type NetworkFilterModel struct {
	Type          types.String `tfsdk:"type"`
	MatchOpposite types.Bool   `tfsdk:"match_opposite"`
	Items         types.Set    `tfsdk:"items"`
}

type PortFilterModel struct {
	Type          types.String    `tfsdk:"type"`
	MatchOpposite types.Bool      `tfsdk:"match_opposite"`
	Items         []PortItemModel `tfsdk:"items"`
}

type PortItemModel struct {
	Type  types.String `tfsdk:"type"`
	Value types.Int32  `tfsdk:"value"`
	Start types.Int32  `tfsdk:"start"`
	Stop  types.Int32  `tfsdk:"stop"`
}

type DomainFilterModel struct {
	Items types.Set `tfsdk:"items"`
}

type IPProtocolScopeModel struct {
	IPVersion      types.String         `tfsdk:"ip_version"`
	ProtocolFilter *ProtocolFilterModel `tfsdk:"protocol_filter"`
}

type ProtocolFilterModel struct {
	Type          types.String `tfsdk:"type"`
	Protocol      types.String `tfsdk:"protocol"`
	MatchOpposite types.Bool   `tfsdk:"match_opposite"`
}
