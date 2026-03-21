package firewall

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

var (
	_ resource.Resource                = &FirewallZoneResource{}
	_ resource.ResourceWithConfigure   = &FirewallZoneResource{}
	_ resource.ResourceWithImportState = &FirewallZoneResource{}
)

type FirewallZoneResource struct {
	client *unifi.Client
}

type FirewallZoneResourceModel struct {
	ID         types.String `tfsdk:"id"`
	Name       types.String `tfsdk:"name"`
	NetworkIDs types.Set    `tfsdk:"network_ids"`
}

func NewFirewallZoneResource() resource.Resource {
	return &FirewallZoneResource{}
}

func (r *FirewallZoneResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewall_zone"
}

func (r *FirewallZoneResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a custom firewall zone.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the firewall zone.",
			},
			"network_ids": schema.SetAttribute{
				ElementType:         types.StringType,
				Required:            true,
				MarkdownDescription: "Set of network IDs assigned to this zone.",
			},
		},
	}
}

func (r *FirewallZoneResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*unifi.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("Expected *unifi.Client, got %T", req.ProviderData))
		return
	}

	r.client = client
}

func (r *FirewallZoneResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan FirewallZoneResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var networkIDs []string
	resp.Diagnostics.Append(plan.NetworkIDs.ElementsAs(ctx, &networkIDs, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	zone := unifi.FirewallZone{
		Name:       plan.Name.ValueString(),
		NetworkIDs: networkIDs,
	}

	created, err := r.client.CreateFirewallZone(zone)
	if err != nil {
		resp.Diagnostics.AddError("Error creating firewall zone", err.Error())
		return
	}

	plan.ID = types.StringValue(created.ID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *FirewallZoneResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state FirewallZoneResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	zone, err := r.client.GetFirewallZone(state.ID.ValueString())
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	state.Name = types.StringValue(zone.Name)
	nids, diags := types.SetValueFrom(ctx, types.StringType, zone.NetworkIDs)
	resp.Diagnostics.Append(diags...)
	state.NetworkIDs = nids

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *FirewallZoneResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan FirewallZoneResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var networkIDs []string
	resp.Diagnostics.Append(plan.NetworkIDs.ElementsAs(ctx, &networkIDs, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	zone := unifi.FirewallZone{
		Name:       plan.Name.ValueString(),
		NetworkIDs: networkIDs,
	}

	_, err := r.client.UpdateFirewallZone(plan.ID.ValueString(), zone)
	if err != nil {
		resp.Diagnostics.AddError("Error updating firewall zone", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *FirewallZoneResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state FirewallZoneResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteFirewallZone(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error deleting firewall zone", err.Error())
		return
	}
}

func (r *FirewallZoneResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
