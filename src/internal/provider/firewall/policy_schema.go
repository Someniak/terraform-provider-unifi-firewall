package firewall

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func (r *FirewallPolicyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"enabled": schema.BoolAttribute{
				Required: true,
			},
			"name": schema.StringAttribute{
				Required: true,
			},
			"description": schema.StringAttribute{
				Optional: true,
			},
			"connection_state_filter": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
			"ipsec_filter": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.OneOf("MATCH_ENCRYPTED", "MATCH_NOT_ENCRYPTED"),
				},
			},
			"logging_enabled": schema.BoolAttribute{
				Required: true,
			},
		},
		Blocks: map[string]schema.Block{
			"schedule": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"mode": schema.StringAttribute{
						Optional: true, // Workaround for validation
						Validators: []validator.String{
							stringvalidator.OneOf("EVERY_DAY", "EVERY_WEEK", "ONE_TIME_ONLY", "CUSTOM"),
						},
					},
					"days_of_week": schema.SetAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
					"start": schema.StringAttribute{
						Optional: true,
					},
					"stop": schema.StringAttribute{
						Optional: true,
					},
				},
				Blocks: map[string]schema.Block{
					"time_range": schema.SingleNestedBlock{
						Attributes: map[string]schema.Attribute{
							"start": schema.StringAttribute{
								Optional: true, // Workaround for validation
							},
							"stop": schema.StringAttribute{
								Optional: true, // Workaround for validation
							},
						},
					},
				},
			},
			"action": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"type": schema.StringAttribute{
						Required: true,
						Validators: []validator.String{
							stringvalidator.OneOf("ALLOW", "BLOCK", "REJECT"),
						},
					},
					"allow_return_traffic": schema.BoolAttribute{
						Optional: true,
						Computed: true,
					},
				},
			},
			"source": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"zone_id": schema.StringAttribute{
						Required: true,
					},
				},
				Blocks: map[string]schema.Block{
					"traffic_filter": schema.SingleNestedBlock{
						Attributes: map[string]schema.Attribute{
							"type": schema.StringAttribute{
								Optional: true, // Workaround for validation
							},
							"mac_address": schema.StringAttribute{
								Optional: true,
							},
						},
						Blocks: map[string]schema.Block{
							"port_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Optional: true, // Workaround for validation
									},
									"match_opposite": schema.BoolAttribute{
										Optional: true, // Workaround for validation
									},
								},
								Blocks: map[string]schema.Block{
									"items": schema.ListNestedBlock{
										NestedObject: schema.NestedBlockObject{
											Attributes: map[string]schema.Attribute{
												"type": schema.StringAttribute{
													Optional: true, // Workaround for validation
												},
												"value": schema.Int32Attribute{
													Optional: true,
												},
												"start": schema.Int32Attribute{
													Optional: true,
												},
												"stop": schema.Int32Attribute{
													Optional: true,
												},
											},
										},
									},
								},
							},
							"ip_address_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Optional: true,
									},
									"match_opposite": schema.BoolAttribute{
										Optional: true, // Workaround for validation
									},
									"items": schema.ListAttribute{
										ElementType: types.StringType,
										Optional:    true, // Workaround for validation
									},
								},
							},
							"mac_address_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Optional: true,
									},
									"match_opposite": schema.BoolAttribute{
										Optional: true, // Workaround for validation
									},
									"items": schema.ListAttribute{
										ElementType: types.StringType,
										Optional:    true, // Workaround for validation
									},
								},
							},
							"network_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Optional: true,
									},
									"match_opposite": schema.BoolAttribute{
										Optional: true, // Workaround for validation
									},
									"items": schema.ListAttribute{
										ElementType: types.StringType,
										Optional:    true, // Workaround for validation
									},
								},
							},
							"domain_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"items": schema.ListAttribute{
										ElementType: types.StringType,
										Optional:    true, // Workaround for validation
									},
								},
							},
						},
					},
				},
			},
			"destination": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"zone_id": schema.StringAttribute{
						Required: true,
					},
				},
				Blocks: map[string]schema.Block{
					"traffic_filter": schema.SingleNestedBlock{
						Attributes: map[string]schema.Attribute{
							"type": schema.StringAttribute{
								Optional: true, // Workaround for validation
							},
							"mac_address": schema.StringAttribute{
								Optional: true,
							},
						},
						Blocks: map[string]schema.Block{
							"port_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Optional: true, // Workaround for validation
									},
									"match_opposite": schema.BoolAttribute{
										Optional: true, // Workaround for validation
									},
								},
								Blocks: map[string]schema.Block{
									"items": schema.ListNestedBlock{
										NestedObject: schema.NestedBlockObject{
											Attributes: map[string]schema.Attribute{
												"type": schema.StringAttribute{
													Optional: true, // Workaround for validation
												},
												"value": schema.Int32Attribute{
													Optional: true,
												},
												"start": schema.Int32Attribute{
													Optional: true,
												},
												"stop": schema.Int32Attribute{
													Optional: true,
												},
											},
										},
									},
								},
							},
							"ip_address_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Optional: true,
									},
									"match_opposite": schema.BoolAttribute{
										Optional: true, // Workaround for validation
									},
									"items": schema.ListAttribute{
										ElementType: types.StringType,
										Optional:    true, // Workaround for validation
									},
								},
							},
							"mac_address_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Optional: true,
									},
									"match_opposite": schema.BoolAttribute{
										Optional: true, // Workaround for validation
									},
									"items": schema.ListAttribute{
										ElementType: types.StringType,
										Optional:    true, // Workaround for validation
									},
								},
							},
							"network_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Optional: true,
									},
									"match_opposite": schema.BoolAttribute{
										Optional: true, // Workaround for validation
									},
									"items": schema.ListAttribute{
										ElementType: types.StringType,
										Optional:    true, // Workaround for validation
									},
								},
							},
							"domain_filter": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"items": schema.ListAttribute{
										ElementType: types.StringType,
										Optional:    true, // Workaround for validation
									},
								},
							},
						},
					},
				},
			},
			"ip_protocol_scope": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"ip_version": schema.StringAttribute{
						Required: true,
						Validators: []validator.String{
							stringvalidator.OneOf("IPV4", "IPV6", "IPV4_AND_IPV6"),
						},
					},
				},
				Blocks: map[string]schema.Block{
					"protocol_filter": schema.SingleNestedBlock{
						Attributes: map[string]schema.Attribute{
							"type": schema.StringAttribute{
								Optional: true,
							},
							"protocol": schema.StringAttribute{
								Optional: true,
							},
							"match_opposite": schema.BoolAttribute{
								Optional: true, // Workaround for validation
							},
						},
					},
				},
			},
		},
	}
}
