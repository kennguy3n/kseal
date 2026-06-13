package cli

import (
	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

func newWebhookCmd(c *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "webhook",
		Short: "Manage tenant webhooks for event fan-out",
	}
	cmd.AddCommand(
		newWebhookRegisterCmd(c),
		newWebhookListCmd(c),
		newWebhookDeleteCmd(c),
	)
	return cmd
}

func newWebhookRegisterCmd(c *CLI) *cobra.Command {
	var url string
	var eventTypes []string
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a webhook endpoint",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			if url == "" {
				return newUsageError("--url is required")
			}
			types, err := parseEventTypes(eventTypes)
			if err != nil {
				return newUsageError("%v", err)
			}
			req := &ksealv1.RegisterWebhookRequest{TenantId: tenant, Url: url, EventTypes: types}
			if c.dryRun {
				c.dryRunNotice("register webhook " + url + " in tenant " + tenant)
				return c.emit(map[string]any{"tenant_id": tenant, "url": url, "event_types": eventTypes}, table{
					Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{{"tenant_id", tenant}, {"url", url}},
				})
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.webhooks().RegisterWebhook(ctx, connect.NewRequest(req))
			if err != nil {
				return err
			}
			w := resp.Msg.GetWebhook()
			return c.emit(newWebhookView(w), webhookTable([]*ksealv1.Webhook{w}))
		},
	}
	cmd.Flags().StringVar(&url, "url", "", "HTTPS endpoint to deliver events to")
	cmd.Flags().StringSliceVar(&eventTypes, "event-type", nil, "event type to subscribe to (repeatable; empty = all)")
	return cmd
}

func newWebhookListCmd(c *CLI) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List webhooks in the tenant",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.webhooks().ListWebhooks(ctx, connect.NewRequest(&ksealv1.ListWebhooksRequest{TenantId: tenant}))
			if err != nil {
				return err
			}
			ws := resp.Msg.GetWebhooks()
			views := make([]webhookView, 0, len(ws))
			for _, w := range ws {
				views = append(views, newWebhookView(w))
			}
			return c.emit(listJSON("webhooks", views, ""), webhookTable(ws))
		},
	}
}

func newWebhookDeleteCmd(c *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <webhook-id>",
		Short: "Delete a webhook",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			if c.dryRun {
				c.dryRunNotice("delete webhook " + args[0] + " in tenant " + tenant)
				return c.emit(map[string]any{"tenant_id": tenant, "id": args[0]}, table{
					Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{{"tenant_id", tenant}, {"id", args[0]}},
				})
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.webhooks().DeleteWebhook(ctx, connect.NewRequest(&ksealv1.DeleteWebhookRequest{TenantId: tenant, Id: args[0]}))
			if err != nil {
				return err
			}
			deleted := resp.Msg.GetDeleted()
			return c.emit(map[string]any{"id": args[0], "deleted": deleted}, table{
				Headers: []string{"ID", "DELETED"}, Rows: [][]string{{args[0], boolStr(deleted)}},
			})
		},
	}
	return cmd
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
