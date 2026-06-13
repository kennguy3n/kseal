package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

func newPolicyPackCmd(c *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pack",
		Short: "List, preview, and apply curated vertical policy packs",
		Long: "Vertical policy packs are curated default policies (fintech, gaming, health, " +
			"media) shipped as client-side data. `list` and `show` are offline; `diff` " +
			"previews a pack against a tenant's active policy; `apply` and `bulk-apply` " +
			"compose ordinary CreatePolicy requests (no dedicated server RPC).",
	}
	cmd.AddCommand(
		newPolicyPackListCmd(c),
		newPolicyPackShowCmd(c),
		newPolicyPackDiffCmd(c),
		newPolicyPackApplyCmd(c),
		newPolicyPackBulkApplyCmd(c),
	)
	return cmd
}

// packListView is the JSON/table projection for `pack list`.
type packListView struct {
	ID          string `json:"id"`
	Vertical    string `json:"vertical"`
	Name        string `json:"name"`
	Mode        string `json:"enforcement_mode"`
	Modules     int    `json:"modules"`
	Description string `json:"description"`
}

func newPolicyPackListCmd(c *CLI) *cobra.Command {
	return &cobra.Command{
		Use:         "list",
		Short:       "List the bundled vertical policy packs (offline)",
		Annotations: map[string]string{annotationLocalOnly: "true"},
		RunE: func(_ *cobra.Command, _ []string) error {
			packs, err := loadPacks()
			if err != nil {
				return err
			}
			views := make([]packListView, 0, len(packs))
			rows := make([][]string, 0, len(packs))
			for _, p := range packs {
				views = append(views, packListView{
					ID: p.ID, Vertical: p.Vertical, Name: p.Name,
					Mode: p.EnforcementMode, Modules: len(p.ModulesEnabled), Description: p.Description,
				})
				rows = append(rows, []string{p.ID, p.Vertical, p.Name, p.EnforcementMode, fmt.Sprintf("%d", len(p.ModulesEnabled))})
			}
			return c.emit(listJSON("packs", views, ""), table{
				Headers: []string{"ID", "VERTICAL", "NAME", "MODE", "MODULES"},
				Rows:    rows,
			})
		},
	}
}

// packDetailView is the full JSON projection for `pack show`.
type packDetailView struct {
	ID             string            `json:"id"`
	Vertical       string            `json:"vertical"`
	Name           string            `json:"name"`
	Description    string            `json:"description"`
	Mode           string            `json:"enforcement_mode"`
	ModulesEnabled []string          `json:"modules_enabled"`
	RiskThresholds map[string]uint32 `json:"risk_thresholds"`
	SignalWeights  map[string]uint32 `json:"signal_weights"`
}

func newPolicyPackShowCmd(c *CLI) *cobra.Command {
	return &cobra.Command{
		Use:         "show <pack-id>",
		Short:       "Show a pack's full contents (offline)",
		Args:        cobra.ExactArgs(1),
		Annotations: map[string]string{annotationLocalOnly: "true"},
		RunE: func(_ *cobra.Command, args []string) error {
			p, err := findPack(args[0])
			if err != nil {
				return err
			}
			view := packDetailView{
				ID: p.ID, Vertical: p.Vertical, Name: p.Name, Description: p.Description,
				Mode: p.EnforcementMode, ModulesEnabled: p.ModulesEnabled,
				RiskThresholds: p.RiskThresholds, SignalWeights: p.SignalWeights,
			}
			rows := [][]string{
				{"id", p.ID},
				{"vertical", p.Vertical},
				{"name", p.Name},
				{"enforcement_mode", p.EnforcementMode},
				{"modules_enabled", strings.Join(p.ModulesEnabled, ", ")},
			}
			for _, lvl := range []string{"CRITICAL", "HIGH_RISK", "MEDIUM_RISK", "LOW_RISK", "TRUSTED"} {
				if v, ok := p.RiskThresholds[lvl]; ok {
					rows = append(rows, []string{"threshold." + lvl, fmt.Sprintf("%d", v)})
				}
			}
			for _, bit := range sortedWeightKeys(p.SignalWeights) {
				rows = append(rows, []string{"weight.bit-" + bit, fmt.Sprintf("%d", p.SignalWeights[bit])})
			}
			return c.emit(view, table{Headers: []string{"FIELD", "VALUE"}, Rows: rows})
		},
	}
}

func newPolicyPackDiffCmd(c *CLI) *cobra.Command {
	var appID string
	cmd := &cobra.Command{
		Use:   "diff <pack-id>",
		Short: "Preview a pack against the tenant's active policy",
		Long:  "Resolve the tenant's currently active policy (for the given --app-id scope) and show the field-level changes the pack would introduce. Read-only.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			pack, err := findPack(args[0])
			if err != nil {
				return err
			}
			diff, err := c.packDiff(cmd.Context(), tenant, appID, pack)
			if err != nil {
				return err
			}
			return c.emit(diff, packDiffTable(diff))
		},
	}
	cmd.Flags().StringVar(&appID, "app-id", "", "app id scope (empty = tenant-wide policy)")
	return cmd
}

func newPolicyPackApplyCmd(c *CLI) *cobra.Command {
	var appID, name string
	var activate bool
	cmd := &cobra.Command{
		Use:   "apply <pack-id>",
		Short: "Apply a pack to the tenant by creating a policy version",
		Long: "Compose a CreatePolicy request from the pack and submit it for the tenant. " +
			"With --activate the new version is also activated. Honors --dry-run, which " +
			"resolves and prints the diff without creating anything.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			pack, err := findPack(args[0])
			if err != nil {
				return err
			}
			policyName := name
			if policyName == "" {
				policyName = pack.defaultPolicyName()
			}
			req, err := pack.createRequest(tenant, policyName, appID)
			if err != nil {
				return err
			}
			if c.dryRun {
				diff, derr := c.packDiff(cmd.Context(), tenant, appID, pack)
				if derr != nil {
					return derr
				}
				action := "create policy " + policyName + " in tenant " + tenant
				if activate {
					action += " and activate it"
				}
				c.dryRunNotice(action)
				return c.emit(diff, packDiffTable(diff))
			}

			ctx, cancel := c.callCtx(cmd.Context())
			resp, err := c.registry().CreatePolicy(ctx, connect.NewRequest(req))
			cancel()
			if err != nil {
				return err
			}
			p := resp.Msg.GetPolicy()
			if activate {
				actCtx, actCancel := c.callCtx(cmd.Context())
				actResp, aerr := c.registry().ActivatePolicy(actCtx, connect.NewRequest(&ksealv1.ActivatePolicyRequest{TenantId: tenant, Id: p.GetId()}))
				actCancel()
				if aerr != nil {
					return aerr
				}
				p = actResp.Msg.GetPolicy()
			}
			return c.emit(newPolicyView(p), policyTable([]*ksealv1.Policy{p}))
		},
	}
	f := cmd.Flags()
	f.StringVar(&appID, "app-id", "", "app id scope (empty = tenant-wide policy)")
	f.StringVar(&name, "name", "", "policy name (default: pack-<id>)")
	f.BoolVar(&activate, "activate", false, "activate the created policy version")
	return cmd
}

// bulkResultView is one tenant's outcome in a bulk pack apply.
type bulkResultView struct {
	TenantID string `json:"tenant_id"`
	Status   string `json:"status"`
	Changes  int    `json:"changes"`
	PolicyID string `json:"policy_id,omitempty"`
	Error    string `json:"error,omitempty"`
}

func newPolicyPackBulkApplyCmd(c *CLI) *cobra.Command {
	var appID, name, tenantsCSV, tenantsFile string
	var activate, force bool
	cmd := &cobra.Command{
		Use:   "bulk-apply <pack-id>",
		Short: "Apply a pack across many tenants (idempotent, batched)",
		Long: "Apply a vertical policy pack to a selection of tenants given via --tenants " +
			"and/or --tenants-file. Idempotent by default: a tenant whose active policy " +
			"already matches the pack is skipped (use --force to apply regardless). Each " +
			"tenant is processed independently so one failure never aborts the batch. " +
			"Honors --dry-run, which reports the per-tenant plan without mutating anything.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pack, err := findPack(args[0])
			if err != nil {
				return err
			}
			tenants, err := resolveTenantSelection(tenantsCSV, tenantsFile)
			if err != nil {
				return err
			}
			policyName := name
			if policyName == "" {
				policyName = pack.defaultPolicyName()
			}

			results := make([]bulkResultView, 0, len(tenants))
			for _, tenant := range tenants {
				results = append(results, c.bulkApplyOne(cmd.Context(), tenant, appID, policyName, pack, activate, force))
			}
			return c.emit(listJSON("results", results, ""), bulkResultTable(results))
		},
	}
	f := cmd.Flags()
	f.StringVar(&appID, "app-id", "", "app id scope applied to every tenant (empty = tenant-wide)")
	f.StringVar(&name, "name", "", "policy name to create in each tenant (default: pack-<id>)")
	f.StringVar(&tenantsCSV, "tenants", "", "comma-separated tenant ids")
	f.StringVar(&tenantsFile, "tenants-file", "", "file of tenant ids (one per line; blank lines and #-comments ignored)")
	f.BoolVar(&activate, "activate", false, "activate the created policy version in each tenant")
	f.BoolVar(&force, "force", false, "apply even when a tenant's active policy already matches the pack")
	return cmd
}

// bulkApplyOne processes a single tenant in a bulk apply, never returning an
// error: a per-tenant failure is captured in the result so the batch continues.
func (c *CLI) bulkApplyOne(ctx context.Context, tenant, appID, policyName string, pack PolicyPack, activate, force bool) bulkResultView {
	res := bulkResultView{TenantID: tenant}
	diff, err := c.packDiff(ctx, tenant, appID, pack)
	if err != nil {
		res.Status = "error"
		res.Error = connectErrMessage(err)
		return res
	}
	res.Changes = len(diff.Changes)
	if !force && !diff.HasChanges() {
		res.Status = "unchanged"
		return res
	}
	if c.dryRun {
		res.Status = "would-apply"
		return res
	}
	req, err := pack.createRequest(tenant, policyName, appID)
	if err != nil {
		res.Status = "error"
		res.Error = connectErrMessage(err)
		return res
	}
	callCtx, cancel := c.callCtx(ctx)
	resp, err := c.registry().CreatePolicy(callCtx, connect.NewRequest(req))
	cancel()
	if err != nil {
		res.Status = "error"
		res.Error = connectErrMessage(err)
		return res
	}
	p := resp.Msg.GetPolicy()
	res.PolicyID = p.GetId()
	res.Status = "applied"
	if activate {
		actCtx, actCancel := c.callCtx(ctx)
		_, aerr := c.registry().ActivatePolicy(actCtx, connect.NewRequest(&ksealv1.ActivatePolicyRequest{TenantId: tenant, Id: p.GetId()}))
		actCancel()
		if aerr != nil {
			res.Status = "error"
			res.Error = connectErrMessage(aerr)
			return res
		}
		res.Status = "activated"
	}
	return res
}

// packDiff resolves the tenant's active policy for the scope and diffs the pack
// against it. A missing active policy is treated as an empty baseline (every
// pack field reads as new) rather than an error.
func (c *CLI) packDiff(ctx context.Context, tenant, appID string, pack PolicyPack) (PackDiff, error) {
	callCtx, cancel := c.callCtx(ctx)
	resp, err := c.registry().GetActivePolicy(callCtx, connect.NewRequest(&ksealv1.GetActivePolicyRequest{TenantId: tenant, AppId: appID}))
	cancel()
	var current policyShape
	if err != nil {
		if connect.CodeOf(err) != connect.CodeNotFound {
			return PackDiff{}, err
		}
		current, _ = shapeFromPolicy(nil)
	} else {
		current, err = shapeFromPolicy(resp.Msg.GetPolicy())
		if err != nil {
			return PackDiff{}, err
		}
	}
	candidate, err := pack.shape()
	if err != nil {
		return PackDiff{}, err
	}
	return diffPolicy(pack.ID, current, candidate), nil
}

// resolveTenantSelection merges and de-duplicates tenant ids from a CSV flag and
// an optional file, preserving first-seen order. At least one id is required.
func resolveTenantSelection(csv, file string) ([]string, error) {
	var raw []string
	raw = append(raw, splitCSV(csv)...)
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read tenants file: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			raw = append(raw, line)
		}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, newUsageError("no tenants selected: pass --tenants and/or --tenants-file")
	}
	return out, nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// connectErrMessage extracts a concise, PII-free message from a Connect error
// for inclusion in bulk results.
func connectErrMessage(err error) string {
	if err == nil {
		return ""
	}
	var ce *connect.Error
	if errors.As(err, &ce) {
		return ce.Message()
	}
	return err.Error()
}

func packDiffTable(d PackDiff) table {
	if len(d.Changes) == 0 {
		return table{Headers: []string{"FIELD", "FROM", "TO"}, Rows: [][]string{{"(no changes)", "", ""}}}
	}
	rows := make([][]string, 0, len(d.Changes))
	for _, ch := range d.Changes {
		rows = append(rows, []string{ch.Field, ch.From, ch.To})
	}
	return table{Headers: []string{"FIELD", "FROM", "TO"}, Rows: rows}
}

func bulkResultTable(results []bulkResultView) table {
	rows := make([][]string, 0, len(results))
	for _, r := range results {
		detail := r.PolicyID
		if r.Error != "" {
			detail = r.Error
		}
		rows = append(rows, []string{r.TenantID, r.Status, fmt.Sprintf("%d", r.Changes), detail})
	}
	return table{Headers: []string{"TENANT", "STATUS", "CHANGES", "DETAIL"}, Rows: rows}
}

// sortedWeightKeys returns the signal-weight bit keys sorted numerically by bit
// index for stable, readable output (falling back to lexical order for any
// non-numeric key, which validation would already have rejected).
func sortedWeightKeys(m map[string]uint32) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		ai, aerr := strconv.ParseUint(keys[i], 10, 32)
		bi, berr := strconv.ParseUint(keys[j], 10, 32)
		if aerr == nil && berr == nil {
			return ai < bi
		}
		return keys[i] < keys[j]
	})
	return keys
}
