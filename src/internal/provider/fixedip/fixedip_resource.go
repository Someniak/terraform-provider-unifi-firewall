package fixedip

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

var (
	_ resource.Resource                = &FixedIPResource{}
	_ resource.ResourceWithConfigure   = &FixedIPResource{}
	_ resource.ResourceWithImportState = &FixedIPResource{}
)

func NewFixedIPResource() resource.Resource {
	return &FixedIPResource{}
}

type FixedIPResource struct {
	client *unifi.Client
}

func (r *FixedIPResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_fixedip"
}

func (r *FixedIPResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a fixed IP (DHCP reservation) for a UniFi client device.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The UniFi client ID.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"mac": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The MAC address of the client device.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"network_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The network ID to assign the fixed IP on.",
			},
			"fixed_ip": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The static IP address to assign.",
			},
			"name": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "The display name for the client device.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *FixedIPResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*unifi.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *unifi.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *FixedIPResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan FixedIPResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	siteID := r.client.SiteID
	mac := strings.ToLower(plan.MAC.ValueString())

	// Look up client by MAC address
	clients, err := r.client.ListClients(siteID)
	if err != nil {
		resp.Diagnostics.AddError("Error listing clients", err.Error())
		return
	}

	var clientID string
	var clientName string
	for _, c := range clients {
		if strings.EqualFold(c.MAC, mac) {
			clientID = c.ID
			clientName = c.Name
			break
		}
	}

	if clientID == "" {
		resp.Diagnostics.AddError(
			"Client not found",
			fmt.Sprintf("No client found with MAC address %q. The device must be known to the UniFi controller.", mac),
		)
		return
	}

	name := plan.Name.ValueString()
	if name == "" {
		name = clientName
	}

	dev, err := r.client.SetClientFixedIP(siteID, clientID, plan.NetworkID.ValueString(), plan.FixedIP.ValueString(), name)
	if err != nil {
		resp.Diagnostics.AddError("Error setting fixed IP", err.Error())
		return
	}

	plan.ID = types.StringValue(dev.ID)
	plan.Name = types.StringValue(dev.Name)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *FixedIPResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state FixedIPResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	siteID := r.client.SiteID

	dev, err := r.client.GetClient(siteID, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading client", err.Error())
		return
	}

	if !dev.UseFixedIP {
		// Fixed IP was removed outside of Terraform
		resp.State.RemoveResource(ctx)
		return
	}

	state.MAC = types.StringValue(dev.MAC)
	state.NetworkID = types.StringValue(dev.NetworkID)
	state.FixedIP = types.StringValue(dev.FixedIP)
	state.Name = types.StringValue(dev.Name)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *FixedIPResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan FixedIPResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	siteID := r.client.SiteID

	name := plan.Name.ValueString()

	dev, err := r.client.SetClientFixedIP(siteID, plan.ID.ValueString(), plan.NetworkID.ValueString(), plan.FixedIP.ValueString(), name)
	if err != nil {
		resp.Diagnostics.AddError("Error updating fixed IP", err.Error())
		return
	}

	plan.Name = types.StringValue(dev.Name)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *FixedIPResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state FixedIPResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	siteID := r.client.SiteID

	err := r.client.UnsetClientFixedIP(siteID, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error removing fixed IP", err.Error())
		return
	}
}

func (r *FixedIPResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
