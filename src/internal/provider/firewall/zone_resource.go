package firewall

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
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
	Origin     types.String `tfsdk:"origin"`
}

func NewFirewallZoneResource() resource.Resource {
	return &FirewallZoneResource{}
}

func (r *FirewallZoneResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewall_zone"
}

func (r *FirewallZoneResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a UniFi firewall zone. Import by UUID or by name (e.g. `terraform import unifi_firewall_zone.example \"My Zone\"`).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The UUID of the firewall zone.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the firewall zone.",
			},
			"network_ids": schema.SetAttribute{
				Optional:            true,
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Set of network UUIDs attached to this zone.",
			},
			"origin": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the zone is USER_DEFINED or SYSTEM_DEFINED.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
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

	apiReq := r.zoneToAPI(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	created, err := r.client.CreateFirewallZone(apiReq)
	if err != nil {
		resp.Diagnostics.AddError("Error creating firewall zone", err.Error())
		return
	}

	r.zoneFromAPI(ctx, created, &plan, &resp.Diagnostics)
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

	r.zoneFromAPI(ctx, zone, &state, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *FirewallZoneResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state FirewallZoneResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiReq := r.zoneToAPI(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	updated, err := r.client.UpdateFirewallZone(state.ID.ValueString(), apiReq)
	if err != nil {
		resp.Diagnostics.AddError("Error updating firewall zone", err.Error())
		return
	}

	r.zoneFromAPI(ctx, updated, &plan, &resp.Diagnostics)
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

// ImportState supports import by UUID or by name.
// If the import ID looks like a UUID, it is used directly.
// Otherwise, it is treated as a zone name and resolved via the API.
func (r *FirewallZoneResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID

	if !isUUID(id) {
		zones, err := r.client.ListFirewallZones()
		if err != nil {
			resp.Diagnostics.AddError("Error listing firewall zones for import", err.Error())
			return
		}

		var found *unifi.FirewallZone
		for i := range zones {
			if strings.EqualFold(zones[i].Name, id) {
				found = &zones[i]
				break
			}
		}

		if found == nil {
			resp.Diagnostics.AddError("Zone not found", fmt.Sprintf("No firewall zone with name %q found", id))
			return
		}

		id = found.ID
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

func (r *FirewallZoneResource) zoneToAPI(ctx context.Context, model FirewallZoneResourceModel, diags *diag.Diagnostics) unifi.FirewallZoneRequest {
	var networkIDs []string
	if !model.NetworkIDs.IsNull() && !model.NetworkIDs.IsUnknown() {
		diags.Append(model.NetworkIDs.ElementsAs(ctx, &networkIDs, false)...)
	}
	if networkIDs == nil {
		networkIDs = []string{}
	}

	return unifi.FirewallZoneRequest{
		Name:       model.Name.ValueString(),
		NetworkIDs: networkIDs,
	}
}

func (r *FirewallZoneResource) zoneFromAPI(ctx context.Context, zone *unifi.FirewallZone, model *FirewallZoneResourceModel, diags *diag.Diagnostics) {
	model.ID = types.StringValue(zone.ID)
	model.Name = types.StringValue(zone.Name)

	networkIDs := zone.NetworkIDs
	if networkIDs == nil {
		networkIDs = []string{}
	}
	setValue, d := types.SetValueFrom(ctx, types.StringType, networkIDs)
	diags.Append(d...)
	model.NetworkIDs = setValue

	if zone.Metadata != nil {
		model.Origin = types.StringValue(zone.Metadata.Origin)
	}
}

// isUUID checks if a string looks like a UUID (8-4-4-4-12 hex pattern).
func isUUID(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return false
	}
	expected := []int{8, 4, 4, 4, 12}
	for i, p := range parts {
		if len(p) != expected[i] {
			return false
		}
		for _, c := range p {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}
