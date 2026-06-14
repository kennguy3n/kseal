package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/tools/datasafety/datasafety"
	"github.com/kennguy3n/kseal/tools/mastg/mastg"
	dscontract "github.com/kennguy3n/kseal/tools/privacy-manifest/contract"
	"github.com/kennguy3n/kseal/tools/privacy-manifest/xcprivacy"
)

// newComplianceCmd assembles the `compliance` command group: local, offline
// store-disclosure generators driven by the embedded SDK data contract and the
// MASVS mapping, plus read-only server queries for audit/compliance state that
// degrade gracefully when the server has not yet shipped the RPC.
func newComplianceCmd(c *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compliance",
		Short: "Generate store-disclosure artifacts and read compliance state",
		Long: "compliance produces self-service NoOps compliance artifacts from the kseal " +
			"SDK data contract and MASVS mapping (iOS privacy manifest, Google Play " +
			"Data-Safety answers, MASTG verification report) and reads compliance/audit " +
			"state from the server. Generators are fully offline and deterministic.",
	}
	cmd.AddCommand(
		newPrivacyManifestCmd(c),
		newDataSafetyCmd(c),
		newMASTGCmd(c),
		newAuditTrailCmd(c),
		newKillSwitchCmd(c),
		newDPRCmd(c),
	)
	return cmd
}

// localOnly marks a generator subcommand as offline so the root skips
// endpoint/API-key resolution.
func localOnly(cmd *cobra.Command) *cobra.Command {
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[annotationLocalOnly] = "true"
	return cmd
}

func writeArtifact(c *CLI, out string, data []byte) error {
	if out == "" {
		_, err := c.out.Write(data)
		return err
	}
	if dir := filepath.Dir(out); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	_, _ = fmt.Fprintf(c.errOut, "wrote %s\n", out)
	return nil
}

// ---- iOS privacy manifest ----

func newPrivacyManifestCmd(c *CLI) *cobra.Command {
	var contractPath, format, out string
	var includeOptional bool
	cmd := &cobra.Command{
		Use:   "privacy-manifest",
		Short: "Generate an Apple PrivacyInfo.xcprivacy for the kseal SDK",
		Long: "Generate a valid Apple privacy manifest (PrivacyInfo.xcprivacy) for the kseal " +
			"SDK from the data contract: privacy-nutrition data types with purposes and the " +
			"required-reason API declarations. Default output is the plist; use --format json " +
			"for a machine-readable summary.",
		RunE: func(_ *cobra.Command, _ []string) error {
			if format != "plist" && format != "json" {
				return newUsageError("invalid --format %q (want plist|json)", format)
			}
			ct, err := dscontract.Load(contractPath)
			if err != nil {
				return err
			}
			m := xcprivacy.Generate(ct, xcprivacy.Options{IncludeOptional: includeOptional})
			if format == "json" {
				data, err := marshalIndent(m)
				if err != nil {
					return err
				}
				return writeArtifact(c, out, data)
			}
			return writeArtifact(c, out, m.XML())
		},
	}
	f := cmd.Flags()
	f.StringVar(&contractPath, "contract", "", "path to a data-contract JSON (default: embedded canonical contract)")
	f.StringVar(&format, "format", "plist", "output format: plist|json")
	f.StringVar(&out, "out", "", "write to this path (default stdout)")
	f.BoolVar(&includeOptional, "include-optional", false, "include data types that are off by default in the contract")
	return localOnly(cmd)
}

// ---- Google Play Data-Safety ----

func newDataSafetyCmd(c *CLI) *cobra.Command {
	var contractPath, format, out string
	var includeOptional bool
	cmd := &cobra.Command{
		Use:   "data-safety",
		Short: "Generate Google Play Data-Safety form answers for the kseal SDK",
		Long: "Generate the Play Console Data-Safety answers from the data contract: data " +
			"types collected/shared, purposes, encryption-in-transit, and deletion support. " +
			"Default output is a human-readable Markdown summary; use --format json for the " +
			"machine-readable form.",
		RunE: func(_ *cobra.Command, _ []string) error {
			if format != "md" && format != "json" {
				return newUsageError("invalid --format %q (want md|json)", format)
			}
			ct, err := dscontract.Load(contractPath)
			if err != nil {
				return err
			}
			form := datasafety.Generate(ct, datasafety.Options{IncludeOptional: includeOptional})
			if format == "json" {
				data, err := form.JSON()
				if err != nil {
					return err
				}
				return writeArtifact(c, out, data)
			}
			return writeArtifact(c, out, form.Markdown())
		},
	}
	f := cmd.Flags()
	f.StringVar(&contractPath, "contract", "", "path to a data-contract JSON (default: embedded canonical contract)")
	f.StringVar(&format, "format", "md", "output format: md|json")
	f.StringVar(&out, "out", "", "write to this path (default stdout)")
	f.BoolVar(&includeOptional, "include-optional", false, "include data types that are off by default in the contract")
	return localOnly(cmd)
}

// ---- MASTG verification runner ----

func newMASTGCmd(c *CLI) *cobra.Command {
	var catalogPath, evidencePath, masvsReportPath, format, out string
	var requirePass bool
	cmd := &cobra.Command{
		Use:   "mastg",
		Short: "Run MASTG verification procedures and emit a per-release report",
		Long: "Map the repo's MASVS controls (docs/masvs-mapping.md) to OWASP MASTG " +
			"verification procedures and evaluate them against per-release evidence: explicit " +
			"assertions (--evidence) and an optional tools/masvs-report overlay (--masvs-report). " +
			"Only failed procedures gate by default; --require-pass also gates on pending device " +
			"procedures. Exit code is non-zero when the release is blocked.",
		RunE: func(_ *cobra.Command, _ []string) error {
			if format != "md" && format != "json" {
				return newUsageError("invalid --format %q (want md|json)", format)
			}
			resolved, err := locateRepoFile(catalogPath)
			if err != nil {
				return err
			}
			md, err := os.ReadFile(resolved)
			if err != nil {
				return fmt.Errorf("read catalog: %w", err)
			}
			cat, err := mastg.ParseCatalog(string(md))
			if err != nil {
				return err
			}
			ev := &mastg.Evidence{}
			if evidencePath != "" {
				data, rerr := os.ReadFile(evidencePath)
				if rerr != nil {
					return fmt.Errorf("read evidence: %w", rerr)
				}
				if ev, err = mastg.LoadEvidence(data); err != nil {
					return err
				}
			}
			if masvsReportPath != "" {
				data, rerr := os.ReadFile(masvsReportPath)
				if rerr != nil {
					return fmt.Errorf("read masvs-report: %w", rerr)
				}
				if err := ev.MergeMASVSReport(data); err != nil {
					return err
				}
			}
			report := cat.Run(ev, mastg.RunOptions{RequirePass: requirePass})
			var rendered []byte
			if format == "json" {
				if rendered, err = report.JSON(); err != nil {
					return err
				}
			} else {
				rendered = report.Markdown()
			}
			if err := writeArtifact(c, out, rendered); err != nil {
				return err
			}
			if report.Gating.Blocked {
				return newBlockedError("release blocked: %d failed, %d pending procedure(s)", report.Gating.Failed, report.Gating.Pending)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&catalogPath, "catalog", "docs/masvs-mapping.md", "path to the MASVS control catalog markdown")
	f.StringVar(&evidencePath, "evidence", "", "path to per-release evidence JSON (explicit MASTG assertions)")
	f.StringVar(&masvsReportPath, "masvs-report", "", "path to a tools/masvs-report JSON to overlay as build evidence")
	f.StringVar(&format, "format", "md", "output format: md|json")
	f.StringVar(&out, "out", "", "write to this path (default stdout)")
	f.BoolVar(&requirePass, "require-pass", false, "strict: pending device procedures also block the release")
	return localOnly(cmd)
}

// locateRepoFile returns path if it exists, else walks up from the working
// directory to find it, so the generators work from any subdirectory.
func locateRepoFile(path string) (string, error) {
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	if filepath.IsAbs(path) {
		return "", fmt.Errorf("file not found: %s", path)
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(dir, path)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("file not found searching up from working dir: %s", path)
		}
		dir = parent
	}
}

// ---- server-backed compliance reads (canonical ComplianceService, graceful degradation) ----

func newAuditTrailCmd(c *CLI) *cobra.Command {
	var action, resourceType string
	var pageSize int32
	cmd := &cobra.Command{
		Use:   "audit-trail",
		Short: "Read the tenant's hash-chained control-plane audit trail",
		Long: "Read operator audit entries for the tenant (control-plane actions; no end-user " +
			"PII), newest first. Optionally filter by --action or --resource-type. Reads the " +
			"canonical ComplianceService; on a server build that predates it the command reports " +
			"\"server capability unavailable\" and exits cleanly.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.compliance().ListAuditEvents(ctx, connect.NewRequest(&ksealv1.ListAuditEventsRequest{
				TenantId: tenant, Action: action, ResourceType: resourceType, PageSize: pageSize,
			}))
			if handled, herr := c.handleCapability(err, "ListAuditEvents"); handled || err != nil {
				return herr
			}
			view := newAuditTrailView(resp.Msg)
			return c.emit(view, auditTrailTable(view))
		},
	}
	f := cmd.Flags()
	f.StringVar(&action, "action", "", "filter to a single action (e.g. policy.activate)")
	f.StringVar(&resourceType, "resource-type", "", "filter to a single resource type")
	f.Int32Var(&pageSize, "page-size", 0, "max entries to return (0 = server default)")
	return cmd
}

func newKillSwitchCmd(c *CLI) *cobra.Command {
	var appID string
	cmd := &cobra.Command{
		Use:   "kill-switch",
		Short: "Read the tenant's kill-switch state",
		Long: "Read the current kill-switch state for the tenant, optionally narrowed to one " +
			"app. Reads the canonical ComplianceService; degrades gracefully when absent.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.compliance().GetKillSwitchState(ctx, connect.NewRequest(&ksealv1.GetKillSwitchStateRequest{
				TenantId: tenant, AppId: appID,
			}))
			if handled, herr := c.handleCapability(err, "GetKillSwitchState"); handled || err != nil {
				return herr
			}
			view := newKillSwitchView(resp.Msg, tenant, appID)
			return c.emit(view, killSwitchTable(view))
		},
	}
	cmd.Flags().StringVar(&appID, "app", "", "narrow to a single app id (default: tenant-wide)")
	return cmd
}

func newDPRCmd(c *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "data-processing-registry",
		Aliases: []string{"dpr"},
		Short:   "Read the tenant's record-of-processing-activities",
		Long: "Read the tenant's data-processing registry (purpose, data categories, legal " +
			"basis, retention, processors). Reads the canonical ComplianceService; degrades " +
			"gracefully when absent.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.compliance().GetDataProcessingRegistry(ctx, connect.NewRequest(&ksealv1.GetDataProcessingRegistryRequest{
				TenantId: tenant,
			}))
			if handled, herr := c.handleCapability(err, "GetDataProcessingRegistry"); handled || err != nil {
				return herr
			}
			view := newDPRView(resp.Msg, tenant)
			return c.emit(view, dprTable(view))
		},
	}
	return cmd
}

// handleCapability implements graceful degradation. It returns (handled, err)
// in idiomatic order: when the server does not implement the RPC (Connect code
// Unimplemented) it prints a clear notice, renders an "available: false" result,
// and returns (true, nil) so the command exits cleanly. For any other outcome it
// returns (false, err) — passing the original error straight back — so callers
// can collapse both branches into `if handled, herr := ...; handled || err != nil { return herr }`.
func (c *CLI) handleCapability(err error, rpc string) (handled bool, _ error) {
	if err == nil {
		return false, nil
	}
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		return false, err
	}
	_, _ = fmt.Fprintf(c.errOut, "server capability unavailable: %s (the server has not deployed this RPC yet)\n", rpc)
	// Always emit a machine-parseable result on stdout so scripts get consistent
	// output across formats (JSON object in --output json, a one-row table
	// otherwise) instead of an empty stdout with a clean exit.
	if c.structured() {
		_ = c.renderStructured(capabilityUnavailable{Available: false, RPC: rpc})
	} else {
		_ = table{Headers: []string{"RPC", "AVAILABLE"}, Rows: [][]string{{rpc, "false"}}}.render(c.out)
	}
	return true, nil
}

type capabilityUnavailable struct {
	Available bool   `json:"available"`
	RPC       string `json:"rpc"`
}
