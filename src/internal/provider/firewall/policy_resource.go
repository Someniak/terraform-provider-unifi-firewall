package firewall

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

type FirewallPolicyResource struct {
	client *unifi.Client
}

func NewFirewallPolicyResource() resource.Resource {
	return &FirewallPolicyResource{}
}

func (r *FirewallPolicyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_fw"
}

func (r *FirewallPolicyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*unifi.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", "Expected *unifi.Client")
		return
	}

	r.client = client
}

func (r *FirewallPolicyResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip if resource is being destroyed
	if req.Plan.Raw.IsNull() {
		return
	}

	var plan FirewallPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Smart Default Logic for allow_return_traffic
	if plan.Action != nil {
		// If allow_return_traffic is unknown (computed) or null (optional, not set), we set default
		// Note: In ModifyPlan, if it was null in config, it might be null or unknown in plan depending on schema.
		// Since it is Optional+Computed, if config is null, plan is Unknown.
		if plan.Action.AllowReturnTraffic.IsUnknown() || plan.Action.AllowReturnTraffic.IsNull() {
			actionType := plan.Action.Type.ValueString()
			// Default to true for ALLOW, false for BLOCK/REJECT
			defaultValue := (actionType == "ALLOW" || actionType == "allow")

			// Update the plan
			plan.Action.AllowReturnTraffic = types.BoolValue(defaultValue)
			resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
		}
	}
}
