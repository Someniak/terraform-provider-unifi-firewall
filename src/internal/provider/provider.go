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
	discoveredID := ""

	if siteInput == "auto" {
		if len(sites) == 1 {
			discoveredID = sites[0].ID
		} else if len(sites) == 0 {
			resp.Diagnostics.AddError("No sites found", "Auto-discovery failed: no sites were found.")
			return
		} else {
			resp.Diagnostics.AddError("Multiple sites found", "Auto-discovery failed: multiple sites exist. Please specify site name or UUID.")
			return
		}
	} else {
		for _, s := range sites {
			if s.ID == siteInput || s.Name == siteInput || s.InternalReference == siteInput {
				discoveredID = s.ID
				break
			}
		}
	}

	if discoveredID == "" {
		resp.Diagnostics.AddError("Site not found", fmt.Sprintf("Could not find site matching: %s", siteInput))
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
	}
}

func (p *UnifiProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		firewall.NewFirewallZoneDataSource,
		NewNetworkDataSource,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &UnifiProvider{
			version: version,
		}
	}
}
