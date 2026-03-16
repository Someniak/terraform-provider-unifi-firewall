package fixedip

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type FixedIPResourceModel struct {
	ID        types.String `tfsdk:"id"`
	MAC       types.String `tfsdk:"mac"`
	NetworkID types.String `tfsdk:"network_id"`
	FixedIP   types.String `tfsdk:"fixed_ip"`
	Name      types.String `tfsdk:"name"`
}
