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
				Required:  true,
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

	// Discovery Logic
	discoveryClient := unifi.NewClient(data.Host.ValueString(), data.APIKey.ValueString(), "", data.Insecure.ValueBool())
	sites, err := discoveryClient.ListSites()
	if err != nil {
		resp.Diagnostics.AddError("Error listing sites for discovery", err.Error())
		return
	}

	siteInput := data.SiteID.ValueString()
	discoveredID, err2 := discoverSiteID(sites, siteInput)
	if err2 != nil {
		resp.Diagnostics.AddError("Site discovery failed", err2.Error())
		return
	}

	client := unifi.NewClient(data.Host.ValueString(), data.APIKey.ValueString(), discoveredID, data.Insecure.ValueBool())

	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *UnifiProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		firewall.NewFirewallPolicyResource,
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

// discoverSiteID resolves a site input (UUID, name, internal reference, or "auto")
// to a concrete site ID from the list of available sites.
func discoverSiteID(sites []unifi.Site, siteInput string) (string, error) {
	if siteInput == "auto" {
		if len(sites) == 1 {
			return sites[0].ID, nil
		} else if len(sites) == 0 {
			return "", fmt.Errorf("auto-discovery failed: no sites were found")
		}
		return "", fmt.Errorf("auto-discovery failed: multiple sites exist, please specify site name or UUID")
	}

	for _, s := range sites {
		if s.ID == siteInput || s.Name == siteInput || s.InternalReference == siteInput {
			return s.ID, nil
		}
	}

	return "", fmt.Errorf("could not find site matching: %s", siteInput)
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &UnifiProvider{
			version: version,
		}
	}
}
