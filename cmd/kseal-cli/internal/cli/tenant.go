package cli

import (
	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

func newTenantCmd(c *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tenant",
		Short: "Manage tenants (control-plane isolation boundaries)",
	}
	cmd.AddCommand(
		newTenantCreateCmd(c),
		newTenantGetCmd(c),
		newTenantListCmd(c),
		newTenantUpdateCmd(c),
	)
	return cmd
}

func newTenantCreateCmd(c *CLI) *cobra.Command {
	var name, slug, tier string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a tenant",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if name == "" || slug == "" {
				return newUsageError("--name and --slug are required")
			}
			req := &ksealv1.CreateTenantRequest{Name: name, Slug: slug, Tier: tier}
			if c.dryRun {
				c.dryRunNotice("create tenant " + slug)
				return c.emit(map[string]any{"name": name, "slug": slug, "tier": tier}, table{
					Headers: []string{"FIELD", "VALUE"},
					Rows:    [][]string{{"name", name}, {"slug", slug}, {"tier", tier}},
				})
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.registry().CreateTenant(ctx, connect.NewRequest(req))
			if err != nil {
				return err
			}
			t := resp.Msg.GetTenant()
			return c.emit(newTenantView(t), tenantTable([]*ksealv1.Tenant{t}))
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "tenant display name")
	cmd.Flags().StringVar(&slug, "slug", "", "unique tenant slug")
	cmd.Flags().StringVar(&tier, "tier", "", "isolation tier: starter|growth|enterprise|regulated")
	return cmd
}

func newTenantGetCmd(c *CLI) *cobra.Command {
	return &cobra.Command{
		Use:   "get <tenant-id>",
		Short: "Get a tenant by id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.registry().GetTenant(ctx, connect.NewRequest(&ksealv1.GetTenantRequest{Id: args[0]}))
			if err != nil {
				return err
			}
			t := resp.Msg.GetTenant()
			return c.emit(newTenantView(t), tenantTable([]*ksealv1.Tenant{t}))
		},
	}
}

func newTenantListCmd(c *CLI) *cobra.Command {
	var pageSize int32
	var pageToken string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List tenants",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.registry().ListTenants(ctx, connect.NewRequest(&ksealv1.ListTenantsRequest{
				PageSize: pageSize, PageToken: pageToken,
			}))
			if err != nil {
				return err
			}
			ts := resp.Msg.GetTenants()
			views := make([]tenantView, 0, len(ts))
			for _, t := range ts {
				views = append(views, newTenantView(t))
			}
			return c.emit(listJSON("tenants", views, resp.Msg.GetNextPageToken()), tenantTable(ts))
		},
	}
	cmd.Flags().Int32Var(&pageSize, "page-size", 0, "max results per page")
	cmd.Flags().StringVar(&pageToken, "page-token", "", "pagination token from a previous response")
	return cmd
}

func newTenantUpdateCmd(c *CLI) *cobra.Command {
	var name, tier, status string
	cmd := &cobra.Command{
		Use:   "update <tenant-id>",
		Short: "Update a tenant's name, tier, or status",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &ksealv1.UpdateTenantRequest{Id: args[0], Name: name, Tier: tier, Status: status}
			if c.dryRun {
				c.dryRunNotice("update tenant " + args[0])
				return c.emit(map[string]any{"id": args[0], "name": name, "tier": tier, "status": status}, table{
					Headers: []string{"FIELD", "VALUE"},
					Rows:    [][]string{{"id", args[0]}, {"name", name}, {"tier", tier}, {"status", status}},
				})
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.registry().UpdateTenant(ctx, connect.NewRequest(req))
			if err != nil {
				return err
			}
			t := resp.Msg.GetTenant()
			return c.emit(newTenantView(t), tenantTable([]*ksealv1.Tenant{t}))
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "new display name")
	cmd.Flags().StringVar(&tier, "tier", "", "new isolation tier")
	cmd.Flags().StringVar(&status, "status", "", "new status: active|suspended|deleted")
	return cmd
}
