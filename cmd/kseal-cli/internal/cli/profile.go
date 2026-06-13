package cli

import (
	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

func newProfileCmd(c *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage protection profiles (reusable module + mode bundles)",
	}
	cmd.AddCommand(
		newProfileCreateCmd(c),
		newProfileListCmd(c),
	)
	return cmd
}

func newProfileCreateCmd(c *CLI) *cobra.Command {
	var name, defaultMode string
	var modules []string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a protection profile",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			if name == "" {
				return newUsageError("--name is required")
			}
			mode, ok := parseEnforcementMode(defaultMode)
			if !ok {
				return newUsageError("invalid --default-mode %q: want observe|step_up|block", defaultMode)
			}
			req := &ksealv1.CreateProtectionProfileRequest{
				TenantId: tenant, Name: name, ModulesEnabled: modules, DefaultMode: mode,
			}
			if c.dryRun {
				c.dryRunNotice("create protection profile " + name + " in tenant " + tenant)
				return c.emit(map[string]any{
					"tenant_id": tenant, "name": name, "modules_enabled": modules, "default_mode": mode.String(),
				}, table{
					Headers: []string{"FIELD", "VALUE"},
					Rows:    [][]string{{"tenant_id", tenant}, {"name", name}, {"default_mode", mode.String()}},
				})
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.registry().CreateProtectionProfile(ctx, connect.NewRequest(req))
			if err != nil {
				return err
			}
			p := resp.Msg.GetProfile()
			return c.emit(newProfileView(p), profileTable([]*ksealv1.ProtectionProfile{p}))
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "profile name")
	cmd.Flags().StringVar(&defaultMode, "default-mode", "observe", "default enforcement mode: observe|step_up|block")
	cmd.Flags().StringSliceVar(&modules, "module", nil, "enabled module (repeatable)")
	return cmd
}

func newProfileListCmd(c *CLI) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List protection profiles in the tenant",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.registry().ListProtectionProfiles(ctx, connect.NewRequest(&ksealv1.ListProtectionProfilesRequest{TenantId: tenant}))
			if err != nil {
				return err
			}
			ps := resp.Msg.GetProfiles()
			views := make([]profileView, 0, len(ps))
			for _, p := range ps {
				views = append(views, newProfileView(p))
			}
			return c.emit(listJSON("profiles", views, ""), profileTable(ps))
		},
	}
}
