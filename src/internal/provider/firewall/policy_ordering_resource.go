package firewall

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

var (
	_ resource.Resource              = &FirewallPolicyOrderingResource{}
	_ resource.ResourceWithConfigure = &FirewallPolicyOrderingResource{}
)

type FirewallPolicyOrderingResource struct {
	client *unifi.Client
}

type FirewallPolicyOrderingResourceModel struct {
	ID        types.String `tfsdk:"id"`
	PolicyIDs types.List   `tfsdk:"policy_ids"`
}

func NewFirewallPolicyOrderingResource() resource.Resource {
	return &FirewallPolicyOrderingResource{}
}

func (r *FirewallPolicyOrderingResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_fw_ordering"
}

func (r *FirewallPolicyOrderingResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the ordering of user-defined firewall policies. Lower index means higher priority.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Identifier for this ordering resource (always 'ordering').",
			},
			"policy_ids": schema.ListAttribute{
				ElementType:         types.StringType,
				Required:            true,
				MarkdownDescription: "Ordered list of firewall policy IDs. First policy has highest priority.",
			},
		},
	}
}

func (r *FirewallPolicyOrderingResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *FirewallPolicyOrderingResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan FirewallPolicyOrderingResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var policyIDs []string
	resp.Diagnostics.Append(plan.PolicyIDs.ElementsAs(ctx, &policyIDs, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.UpdateFirewallPolicyOrdering(unifi.FirewallPolicyOrdering{PolicyIDs: policyIDs})
	if err != nil {
		resp.Diagnostics.AddError("Error setting firewall policy ordering", err.Error())
		return
	}

	plan.ID = types.StringValue("ordering")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *FirewallPolicyOrderingResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state FirewallPolicyOrderingResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyIDs, err := r.client.GetFirewallPolicyOrdering()
	if err != nil {
		resp.Diagnostics.AddError("Error reading firewall policy ordering", err.Error())
		return
	}

	listVal, diags := types.ListValueFrom(ctx, types.StringType, policyIDs)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.PolicyIDs = listVal
	state.ID = types.StringValue("ordering")
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *FirewallPolicyOrderingResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan FirewallPolicyOrderingResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var policyIDs []string
	resp.Diagnostics.Append(plan.PolicyIDs.ElementsAs(ctx, &policyIDs, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.UpdateFirewallPolicyOrdering(unifi.FirewallPolicyOrdering{PolicyIDs: policyIDs})
	if err != nil {
		resp.Diagnostics.AddError("Error updating firewall policy ordering", err.Error())
		return
	}

	plan.ID = types.StringValue("ordering")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *FirewallPolicyOrderingResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Ordering is inherent to the system — deletion is a no-op.
	// The policies themselves still exist; we just stop managing their order.
}
