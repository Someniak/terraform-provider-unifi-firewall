package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/provider/firewall"
	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/provider/fixedip"
	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

type UnifiProvider struct {
	version string
}

type UnifiProviderModel struct {
	Host     types.String `tfsdk:"host"`
	APIKey   types.String `tfsdk:"api_key"`
	Username types.String `tfsdk:"username"`
	Password types.String `tfsdk:"password"`
	SiteID   types.String `tfsdk:"site_id"`
	Insecure types.Bool   `tfsdk:"insecure"`
}

func (p *UnifiProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "unifi"
	resp.Version = p.version
}

func (p *UnifiProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"host": schema.StringAttribute{
				Required: true,
			},
			"api_key": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
			},
			"username": schema.StringAttribute{
				Optional: true,
			},
			"password": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
			},
			"site_id": schema.StringAttribute{
				Required: true,
			},
			"insecure": schema.BoolAttribute{
				Optional: true,
			},
		},
	}
}

func (p *UnifiProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data UnifiProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasAPIKey := !data.APIKey.IsNull() && !data.APIKey.IsUnknown() && data.APIKey.ValueString() != ""
	hasUsername := !data.Username.IsNull() && !data.Username.IsUnknown() && data.Username.ValueString() != ""
	hasPassword := !data.Password.IsNull() && !data.Password.IsUnknown() && data.Password.ValueString() != ""

	if hasAPIKey && (hasUsername || hasPassword) {
		resp.Diagnostics.AddError(
			"Conflicting authentication",
			"Specify either 'api_key' or 'username'+'password', not both.",
		)
		return
	}
	if !hasAPIKey && !hasUsername {
		resp.Diagnostics.AddError(
			"Missing authentication",
			"Either 'api_key' or both 'username' and 'password' must be provided.",
		)
		return
	}
	if hasUsername && !hasPassword {
		resp.Diagnostics.AddError(
			"Missing password",
			"'password' is required when 'username' is specified.",
		)
		return
	}

	// Create the appropriate client for site discovery
	var discoveryClient *unifi.Client
	if hasAPIKey {
		discoveryClient = unifi.NewClient(data.Host.ValueString(), data.APIKey.ValueString(), "", data.Insecure.ValueBool())
	} else {
		var err error
		discoveryClient, err = unifi.NewClientWithCredentials(
			data.Host.ValueString(),
			data.Username.ValueString(),
			data.Password.ValueString(),
			"",
			data.Insecure.ValueBool(),
		)
		if err != nil {
			resp.Diagnostics.AddError("Authentication failed", err.Error())
			return
		}
	}

	sites, err := discoveryClient.ListSites()
	if err != nil {
		resp.Diagnostics.AddError("Error listing sites for discovery", err.Error())
		return
	}

	siteInput := data.SiteID.ValueString()
	discoveredSite, err := discoverSite(sites, siteInput)
	if err != nil {
		resp.Diagnostics.AddError("Site discovery failed", err.Error())
		return
	}

	// Create the final client with the discovered site ID
	var client *unifi.Client
	if hasAPIKey {
		client = unifi.NewClient(data.Host.ValueString(), data.APIKey.ValueString(), discoveredSite.ID, data.Insecure.ValueBool())
	} else {
		// Reuse the discovery client — just update the site ID to avoid a second login
		discoveryClient.SiteID = discoveredSite.ID
		client = discoveryClient
	}
	client.SiteReference = discoveredSite.InternalReference
	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *UnifiProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		firewall.NewFirewallPolicyResource,
		firewall.NewFirewallZoneResource,
		firewall.NewDNSPolicyResource,
		fixedip.NewFixedIPResource,
	}
}

func (p *UnifiProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		firewall.NewFirewallZoneDataSource,
		NewNetworkDataSource,
	}
}

// discoverSite resolves a site input (UUID, name, internal reference, or "auto")
// to a concrete Site from the list of available sites.
func discoverSite(sites []unifi.Site, siteInput string) (unifi.Site, error) {
	if siteInput == "auto" {
		if len(sites) == 1 {
			return sites[0], nil
		} else if len(sites) == 0 {
			return unifi.Site{}, fmt.Errorf("auto-discovery failed: no sites were found")
		}
		return unifi.Site{}, fmt.Errorf("auto-discovery failed: multiple sites exist, please specify site name or UUID")
	}

	for _, s := range sites {
		if s.ID == siteInput || s.Name == siteInput || s.InternalReference == siteInput {
			return s, nil
		}
	}

	return unifi.Site{}, fmt.Errorf("could not find site matching: %s", siteInput)
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &UnifiProvider{
			version: version,
		}
	}
}
