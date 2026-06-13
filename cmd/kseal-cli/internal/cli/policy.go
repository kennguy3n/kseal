package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

func newPolicyCmd(c *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Author, validate, activate, and simulate enforcement policies",
	}
	cmd.AddCommand(
		newPolicyAuthorCmd(c),
		newPolicyValidateCmd(c),
		newPolicyActivateCmd(c),
		newPolicySimulateCmd(c),
		newPolicyListCmd(c),
		newPolicyGetActiveCmd(c),
	)
	return cmd
}

// readPolicyFile loads and decodes an authoring policy file.
func readPolicyFile(path string) (*PolicyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	var pf PolicyFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, newUsageError("parse policy file: %v", err)
	}
	return &pf, nil
}

func newPolicyAuthorCmd(c *CLI) *cobra.Command {
	var file, appID, name string
	cmd := &cobra.Command{
		Use:   "author",
		Short: "Create a policy version from an authoring file",
		Long:  "Create a new policy version from a JSON authoring file. The file is validated before submission.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			if file == "" {
				return newUsageError("--file is required")
			}
			pf, err := readPolicyFile(file)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("app-id") {
				pf.AppID = appID
			}
			if cmd.Flags().Changed("name") {
				pf.Name = name
			}
			if problems := pf.Validate(); len(problems) > 0 {
				return newUsageError("policy file is invalid:\n  - %s", joinLines(problems))
			}
			mode, _ := parseEnforcementMode(pf.EnforcementMode)
			req := &ksealv1.CreatePolicyRequest{
				TenantId: tenant, AppId: pf.AppID, Name: pf.Name, EnforcementMode: mode,
				Rules: pf.rulesString(), RiskThresholds: pf.thresholdsString(), ModulesEnabled: pf.ModulesEnabled,
			}
			if c.dryRun {
				c.dryRunNotice("create policy " + pf.Name + " in tenant " + tenant)
				return c.emit(map[string]any{
					"tenant_id": tenant, "app_id": pf.AppID, "name": pf.Name,
					"enforcement_mode": mode.String(), "modules_enabled": pf.ModulesEnabled,
				}, table{
					Headers: []string{"FIELD", "VALUE"},
					Rows: [][]string{
						{"tenant_id", tenant}, {"app_id", pf.AppID}, {"name", pf.Name}, {"enforcement_mode", mode.String()},
					},
				})
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.registry().CreatePolicy(ctx, connect.NewRequest(req))
			if err != nil {
				return err
			}
			p := resp.Msg.GetPolicy()
			return c.emit(newPolicyView(p), policyTable([]*ksealv1.Policy{p}))
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "policy authoring file (JSON)")
	cmd.Flags().StringVar(&appID, "app-id", "", "app id (overrides the file; empty = tenant-wide)")
	cmd.Flags().StringVar(&name, "name", "", "policy name (overrides the file)")
	return cmd
}

func newPolicyValidateCmd(c *CLI) *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:         "validate",
		Short:       "Validate a policy authoring file locally (no server call)",
		Annotations: map[string]string{annotationLocalOnly: "true"},
		RunE: func(_ *cobra.Command, _ []string) error {
			if file == "" {
				return newUsageError("--file is required")
			}
			pf, err := readPolicyFile(file)
			if err != nil {
				return err
			}
			problems := pf.Validate()
			result := struct {
				Valid    bool     `json:"valid"`
				Problems []string `json:"problems"`
			}{Valid: len(problems) == 0, Problems: problems}
			if result.Problems == nil {
				result.Problems = []string{}
			}
			tbl := table{Headers: []string{"VALID", "PROBLEMS"}, Rows: [][]string{{fmt.Sprintf("%t", result.Valid), fmt.Sprintf("%d", len(problems))}}}
			if err := c.emit(result, tbl); err != nil {
				return err
			}
			if len(problems) > 0 {
				// An invalid policy file is an input error: exit 2 (ExitUsage),
				// matching "policy author"'s invalid-file path and the documented
				// exit-code contract. The problem list is already rendered above.
				return usageError{err: invalidPolicyError{count: len(problems)}}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "policy authoring file (JSON)")
	return cmd
}

// invalidPolicyError signals validation failure with a CI-friendly exit code
// while keeping the (already rendered) problem list as the user-facing output.
type invalidPolicyError struct{ count int }

func (e invalidPolicyError) Error() string {
	return fmt.Sprintf("policy validation failed: %d problem(s)", e.count)
}

func newPolicyActivateCmd(c *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "activate <policy-id>",
		Short: "Activate a policy version for the tenant",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			if c.dryRun {
				c.dryRunNotice("activate policy " + args[0] + " in tenant " + tenant)
				return c.emit(map[string]any{"tenant_id": tenant, "id": args[0]}, table{
					Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{{"tenant_id", tenant}, {"id", args[0]}},
				})
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.registry().ActivatePolicy(ctx, connect.NewRequest(&ksealv1.ActivatePolicyRequest{TenantId: tenant, Id: args[0]}))
			if err != nil {
				return err
			}
			p := resp.Msg.GetPolicy()
			return c.emit(newPolicyView(p), policyTable([]*ksealv1.Policy{p}))
		},
	}
	return cmd
}

func newPolicyListCmd(c *CLI) *cobra.Command {
	var appID string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List policy versions for the tenant",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.registry().ListPolicies(ctx, connect.NewRequest(&ksealv1.ListPoliciesRequest{TenantId: tenant, AppId: appID}))
			if err != nil {
				return err
			}
			ps := resp.Msg.GetPolicies()
			views := make([]policyView, 0, len(ps))
			for _, p := range ps {
				views = append(views, newPolicyView(p))
			}
			return c.emit(listJSON("policies", views, ""), policyTable(ps))
		},
	}
	cmd.Flags().StringVar(&appID, "app-id", "", "filter by app id (empty = tenant-wide)")
	return cmd
}

func newPolicyGetActiveCmd(c *CLI) *cobra.Command {
	var appID string
	cmd := &cobra.Command{
		Use:   "get-active",
		Short: "Get the active policy for the tenant/app",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.registry().GetActivePolicy(ctx, connect.NewRequest(&ksealv1.GetActivePolicyRequest{TenantId: tenant, AppId: appID}))
			if err != nil {
				return err
			}
			p := resp.Msg.GetPolicy()
			return c.emit(newPolicyView(p), policyTable([]*ksealv1.Policy{p}))
		},
	}
	cmd.Flags().StringVar(&appID, "app-id", "", "app id (empty = tenant-wide)")
	return cmd
}

func newPolicySimulateCmd(c *CLI) *cobra.Command {
	var candidateFile, appID string
	var startTime, endTime int64
	var maxEvents int
	cmd := &cobra.Command{
		Use:   "simulate",
		Short: "Simulate a candidate policy against recent traffic",
		Long: "Replay recent risk events for the tenant/app and report how decisions would " +
			"change under a candidate policy versus the currently active policy. Reuses the " +
			"server's authoritative risk scoring so results match production enforcement.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			if candidateFile == "" {
				return newUsageError("--candidate-file is required")
			}
			pf, err := readPolicyFile(candidateFile)
			if err != nil {
				return err
			}
			if problems := pf.Validate(); len(problems) > 0 {
				return newUsageError("candidate policy is invalid:\n  - %s", joinLines(problems))
			}
			candidate, err := pf.spec()
			if err != nil {
				return newUsageError("%v", err)
			}

			// --timeout is a per-request bound (see flag help), so each RPC below
			// gets its own deadline rather than sharing one across the whole
			// simulation (which could starve later event pages on large fleets).
			parent := cmd.Context()

			// Resolve the current active policy spec; a missing active policy is
			// treated as an empty (permissive) baseline rather than an error.
			current := PolicySpec{Thresholds: map[string]uint32{}, Weights: map[uint32]uint32{}}
			actCtx, actCancel := c.callCtx(parent)
			actResp, aerr := c.registry().GetActivePolicy(actCtx, connect.NewRequest(&ksealv1.GetActivePolicyRequest{TenantId: tenant, AppId: appID}))
			actCancel()
			if aerr != nil {
				if connect.CodeOf(aerr) != connect.CodeNotFound {
					return aerr
				}
			} else {
				current, err = specFromPolicy(actResp.Msg.GetPolicy())
				if err != nil {
					return err
				}
			}

			bitsets, err := c.collectRiskBits(parent, tenant, appID, startTime, endTime, maxEvents)
			if err != nil {
				return err
			}
			report := simulate(bitsets, current, candidate)
			tbl := table{Headers: []string{"METRIC", "VALUE"}, Rows: [][]string{
				{"total_events", fmt.Sprintf("%d", report.Total)},
				{"changed", fmt.Sprintf("%d", report.Changed)},
				{"newly_blocked", fmt.Sprintf("%d", report.NewlyBlocked)},
				{"newly_allowed", fmt.Sprintf("%d", report.NewlyAllowed)},
			}}
			tbl.Rows = append(tbl.Rows, []string{"--- current ---", ""})
			tbl.Rows = append(tbl.Rows, sortedCountRows(report.CurrentCounts)...)
			tbl.Rows = append(tbl.Rows, []string{"--- candidate ---", ""})
			tbl.Rows = append(tbl.Rows, sortedCountRows(report.CandidateCounts)...)
			return c.emit(report, tbl)
		},
	}
	f := cmd.Flags()
	f.StringVar(&candidateFile, "candidate-file", "", "candidate policy authoring file (JSON)")
	f.StringVar(&appID, "app-id", "", "app id to scope traffic (empty = all apps in tenant)")
	f.Int64Var(&startTime, "start", 0, "inclusive lower time bound (unix millis; 0 = unbounded)")
	f.Int64Var(&endTime, "end", 0, "inclusive upper time bound (unix millis; 0 = unbounded)")
	f.IntVar(&maxEvents, "max-events", 5000, "maximum events to replay")
	return cmd
}

// collectRiskBits pages through ListEvents and gathers risk bitsets, bounded by
// maxEvents to keep simulation fast and memory-stable on large fleets.
func (c *CLI) collectRiskBits(ctx context.Context, tenant, appID string, start, end int64, maxEvents int) ([]uint64, error) {
	if maxEvents <= 0 {
		maxEvents = 5000
	}
	var bits []uint64
	pageToken := ""
	for len(bits) < maxEvents {
		pageSize := int32(500)
		if remaining := maxEvents - len(bits); remaining < int(pageSize) {
			pageSize = int32(remaining)
		}
		pageCtx, pageCancel := c.callCtx(ctx)
		resp, err := c.query().ListEvents(pageCtx, connect.NewRequest(&ksealv1.ListEventsRequest{
			TenantId: tenant, AppId: appID, StartTime: start, EndTime: end,
			PageSize: pageSize, PageToken: pageToken,
		}))
		pageCancel()
		if err != nil {
			return nil, err
		}
		for _, e := range resp.Msg.GetEvents() {
			bits = append(bits, e.GetRiskBits())
		}
		pageToken = resp.Msg.GetNextPageToken()
		if pageToken == "" || len(resp.Msg.GetEvents()) == 0 {
			break
		}
	}
	return bits, nil
}

func joinLines(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += "\n  - "
		}
		out += s
	}
	return out
}
