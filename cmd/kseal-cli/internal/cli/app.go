package cli

import (
	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

func newAppCmd(c *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "app",
		Short: "Manage apps within a tenant",
	}
	cmd.AddCommand(
		newAppCreateCmd(c),
		newAppGetCmd(c),
		newAppListCmd(c),
	)
	return cmd
}

func newAppCreateCmd(c *CLI) *cobra.Command {
	var name, platform, packageID string
	var signingIdentities []string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Register an app",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			if name == "" || packageID == "" {
				return newUsageError("--name and --package-id are required")
			}
			plat, err := parsePlatform(platform)
			if err != nil {
				return newUsageError("%v", err)
			}
			req := &ksealv1.CreateAppRequest{
				TenantId: tenant, Name: name, Platform: plat,
				PackageId: packageID, SigningIdentities: signingIdentities,
			}
			if c.dryRun {
				c.dryRunNotice("create app " + packageID + " in tenant " + tenant)
				return c.emit(map[string]any{
					"tenant_id": tenant, "name": name, "platform": plat.String(),
					"package_id": packageID, "signing_identities": signingIdentities,
				}, table{
					Headers: []string{"FIELD", "VALUE"},
					Rows: [][]string{
						{"tenant_id", tenant}, {"name", name}, {"platform", plat.String()}, {"package_id", packageID},
					},
				})
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.registry().CreateApp(ctx, connect.NewRequest(req))
			if err != nil {
				return err
			}
			a := resp.Msg.GetApp()
			return c.emit(newAppView(a), appTable([]*ksealv1.App{a}))
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "app display name")
	cmd.Flags().StringVar(&platform, "platform", "", "platform: android|ios")
	cmd.Flags().StringVar(&packageID, "package-id", "", "Android package name or iOS bundle id")
	cmd.Flags().StringSliceVar(&signingIdentities, "signing-identity", nil, "allowed signing identity (repeatable)")
	return cmd
}

func newAppGetCmd(c *CLI) *cobra.Command {
	return &cobra.Command{
		Use:   "get <app-id>",
		Short: "Get an app by id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.registry().GetApp(ctx, connect.NewRequest(&ksealv1.GetAppRequest{TenantId: tenant, Id: args[0]}))
			if err != nil {
				return err
			}
			a := resp.Msg.GetApp()
			return c.emit(newAppView(a), appTable([]*ksealv1.App{a}))
		},
	}
}

func newAppListCmd(c *CLI) *cobra.Command {
	var pageSize int32
	var pageToken string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List apps in the tenant",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.registry().ListApps(ctx, connect.NewRequest(&ksealv1.ListAppsRequest{
				TenantId: tenant, PageSize: pageSize, PageToken: pageToken,
			}))
			if err != nil {
				return err
			}
			as := resp.Msg.GetApps()
			views := make([]appView, 0, len(as))
			for _, a := range as {
				views = append(views, newAppView(a))
			}
			return c.emit(listJSON("apps", views, resp.Msg.GetNextPageToken()), appTable(as))
		},
	}
	cmd.Flags().Int32Var(&pageSize, "page-size", 0, "max results per page")
	cmd.Flags().StringVar(&pageToken, "page-token", "", "pagination token from a previous response")
	return cmd
}
