package firewall

import (
	"context"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/someniak/terraform-provider-unifi-firewall/src/internal/unifi"
)

func mapTrafficFilterToAPI(ctx context.Context, tf *TrafficFilterModel) *unifi.TrafficFilter {
	if tf == nil {
		return nil
	}

	apiTF := &unifi.TrafficFilter{
		Type: tf.Type.ValueString(),
	}

	if !tf.MACAddress.IsNull() {
		apiTF.MACAddressFilter = tf.MACAddress.ValueString()
	}

	if tf.PortFilter != nil {
		apiTF.PortFilter = &unifi.PortFilter{
			Type:          tf.PortFilter.Type.ValueString(),
			MatchOpposite: tf.PortFilter.MatchOpposite.ValueBool(),
		}
		for _, item := range tf.PortFilter.Items {
			pi := unifi.PortItem{
				Type: item.Type.ValueString(),
			}
			if !item.Value.IsNull() {
				pi.Value = int(item.Value.ValueInt32())
			}
			if !item.Start.IsNull() {
				pi.Start = int(item.Start.ValueInt32())
			}
			if !item.Stop.IsNull() {
				pi.Stop = int(item.Stop.ValueInt32())
			}
			apiTF.PortFilter.Items = append(apiTF.PortFilter.Items, pi)
		}
	}

	if tf.IPAddressFilter != nil {
		var items []string
		tf.IPAddressFilter.Items.ElementsAs(ctx, &items, false)
		apiTF.IPAddressFilter = &unifi.IPAddressFilter{
			Type:          tf.IPAddressFilter.Type.ValueString(),
			MatchOpposite: tf.IPAddressFilter.MatchOpposite.ValueBool(),
		}
		for _, item := range items {
			itemType := "IP_ADDRESS"
			if strings.Contains(item, "/") {
				itemType = "SUBNET"
			}
			apiTF.IPAddressFilter.Items = append(apiTF.IPAddressFilter.Items, unifi.IPAddressItem{
				Type:  itemType,
				Value: item,
			})
		}
	}

	if tf.MACAddressFilter != nil {
		var items []string
		tf.MACAddressFilter.Items.ElementsAs(ctx, &items, false)
		apiTF.MACAddressFilter = &unifi.MACAddressFilter{
			MACAddresses: items,
		}
	}

	if tf.NetworkFilter != nil {
		var items []string
		tf.NetworkFilter.Items.ElementsAs(ctx, &items, false)
		apiTF.NetworkFilter = &unifi.NetworkFilter{
			MatchOpposite: tf.NetworkFilter.MatchOpposite.ValueBool(),
			NetworkIDs:    items,
		}
	}

	if tf.DomainFilter != nil {
		var items []string
		tf.DomainFilter.Items.ElementsAs(ctx, &items, false)
		apiTF.DomainFilter = &unifi.DomainFilter{
			Type: "DOMAINS", // Assuming fixed type for now as per previous code
		}
		apiTF.DomainFilter.Domains = items
	}

	return apiTF
}

func mapTrafficFilterFromAPI(ctx context.Context, apiTF *unifi.TrafficFilter) *TrafficFilterModel {
	if apiTF == nil {
		return nil
	}

	tf := &TrafficFilterModel{
		Type: types.StringValue(apiTF.Type),
	}

	if v, ok := apiTF.MACAddressFilter.(string); ok {
		tf.MACAddress = types.StringValue(v)
	}

	// Handle polymorphic MACAddressFilter
	if macFilter, ok := apiTF.MACAddressFilter.(*unifi.MACAddressFilter); ok {
		tf.MACAddressFilter = &MACAddressFilterModel{
			Type:          types.StringValue("MAC_ADDRESSES"),
			MatchOpposite: types.BoolValue(false),
		}
		tf.MACAddressFilter.Items, _ = types.SetValueFrom(ctx, types.StringType, macFilter.MACAddresses)
	} else if listMacs, ok := apiTF.MACAddressFilter.(map[string]interface{}); ok {
		// Fallback for raw map if needed (e.g. from generic JSON unmarshal)
		if macs, ok := listMacs["macAddresses"].([]interface{}); ok {
			var ms []string
			for _, m := range macs {
				ms = append(ms, m.(string))
			}
			tf.MACAddressFilter = &MACAddressFilterModel{
				Type:          types.StringValue("MAC_ADDRESSES"),
				MatchOpposite: types.BoolValue(false),
			}
			tf.MACAddressFilter.Items, _ = types.SetValueFrom(ctx, types.StringType, ms)
		}
	}

	if apiTF.PortFilter != nil {
		var items []PortItemModel
		for _, item := range apiTF.PortFilter.Items {
			pi := PortItemModel{
				Type: types.StringValue(item.Type),
			}
			if item.Value != 0 {
				pi.Value = types.Int32Value(int32(item.Value))
			}
			if item.Start != 0 {
				pi.Start = types.Int32Value(int32(item.Start))
			}
			if item.Stop != 0 {
				pi.Stop = types.Int32Value(int32(item.Stop))
			}
			items = append(items, pi)
		}

		// Sort items to avoid "ghost" changes if the API Returns them in a different order
		sort.Slice(items, func(i, j int) bool {
			if items[i].Value.ValueInt32() != items[j].Value.ValueInt32() {
				return items[i].Value.ValueInt32() < items[j].Value.ValueInt32()
			}
			if items[i].Start.ValueInt32() != items[j].Start.ValueInt32() {
				return items[i].Start.ValueInt32() < items[j].Start.ValueInt32()
			}
			return items[i].Stop.ValueInt32() < items[j].Stop.ValueInt32()
		})

		tf.PortFilter = &PortFilterModel{
			Type:          types.StringValue(apiTF.PortFilter.Type),
			MatchOpposite: types.BoolValue(apiTF.PortFilter.MatchOpposite),
			Items:         items,
		}
	}

	if apiTF.IPAddressFilter != nil {
		tf.IPAddressFilter = &IPAddressFilterModel{
			Type:          types.StringValue(apiTF.IPAddressFilter.Type),
			MatchOpposite: types.BoolValue(apiTF.IPAddressFilter.MatchOpposite),
		}
		var ms []string
		for _, item := range apiTF.IPAddressFilter.Items {
			ms = append(ms, item.Value)
		}
		tf.IPAddressFilter.Items, _ = types.SetValueFrom(ctx, types.StringType, ms)
	}

	if apiTF.NetworkFilter != nil {
		tf.NetworkFilter = &NetworkFilterModel{
			Type:          types.StringValue("NETWORK"),
			MatchOpposite: types.BoolValue(apiTF.NetworkFilter.MatchOpposite),
		}
		tf.NetworkFilter.Items, _ = types.SetValueFrom(ctx, types.StringType, apiTF.NetworkFilter.NetworkIDs)
	}

	if apiTF.DomainFilter != nil {
		tf.DomainFilter = &DomainFilterModel{}
		tf.DomainFilter.Items, _ = types.SetValueFrom(ctx, types.StringType, apiTF.DomainFilter.Domains)
	}

	return tf
}
