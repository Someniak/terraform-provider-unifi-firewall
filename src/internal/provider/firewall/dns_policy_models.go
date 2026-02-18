package firewall

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type DNSPolicyResourceModel struct {
	ID      types.String `tfsdk:"id"`
	SiteID  types.String `tfsdk:"site_id"`
	Type    types.String `tfsdk:"type"`
	Domain  types.String `tfsdk:"domain"`
	Enabled types.Bool   `tfsdk:"enabled"`

	// Forwarding
	Target types.String `tfsdk:"target"`

	// Record fields
	// Note: These map to the 'record' map in the API JSON.
	// We expose them as top-level attributes for better UX, or we could group them.
	// Flattening seems appropriate if they are mutually exclusive based on Type.
	IPAddress types.String `tfsdk:"ip_address"` // A, AAAA
	CNAME     types.String `tfsdk:"cname"`      // CNAME
	Priority  types.Int64  `tfsdk:"priority"`   // MX, SRV
	Weight    types.Int64  `tfsdk:"weight"`     // SRV
	Port      types.Int64  `tfsdk:"port"`       // SRV
	Text      types.String `tfsdk:"text"`       // TXT
	TTL       types.Int64  `tfsdk:"ttl"`        // Common
}
