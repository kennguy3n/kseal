package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// BuildManifest is the on-disk artifact produced by the build-time plugins
// (Gradle/Xcode). `build register` consumes it to record an immutable build in
// the registry. `manifest` is free-form provenance (module set, transforms);
// it is stored verbatim as a JSON string on the Build record.
type BuildManifest struct {
	AppID               string          `json:"app_id"`
	BuildHash           string          `json:"build_hash"`
	VersionName         string          `json:"version_name"`
	VersionCode         int64           `json:"version_code"`
	ProtectionProfileID string          `json:"protection_profile_id"`
	Manifest            json.RawMessage `json:"manifest,omitempty"`
}

func newBuildCmd(c *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Manage protected builds",
	}
	cmd.AddCommand(
		newBuildRegisterCmd(c),
		newBuildGetCmd(c),
		newBuildListCmd(c),
		newBuildMASVSCmd(c),
	)
	return cmd
}

func newBuildMASVSCmd(c *CLI) *cobra.Command {
	return &cobra.Command{
		Use:   "masvs <build-id>",
		Short: "Show a build's MASVS evidence report",
		Long: "Fetch a registered build and render an OWASP MASVS evidence report: the " +
			"build-hash proof, manifest module/transform provenance, and per-category " +
			"coverage derived from the module set. Read-only; gaps and limits of the " +
			"available evidence are reported explicitly.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.registry().GetBuild(ctx, connect.NewRequest(&ksealv1.GetBuildRequest{TenantId: tenant, Id: args[0]}))
			if err != nil {
				return err
			}
			report := buildMASVSReport(resp.Msg.GetBuild())
			return c.emit(report, masvsReportTable(report))
		},
	}
}

func masvsReportTable(r MASVSReport) table {
	rows := [][]string{
		{"build_id", r.BuildID},
		{"app_id", r.AppID},
		{"build_hash", r.BuildHash},
		{"version", r.VersionName},
		{"coverage", fmt.Sprintf("%d/%d categories", r.CoveredCount, r.TotalCategories)},
	}
	for _, cat := range r.Categories {
		status := "gap"
		if cat.Covered {
			status = strings.Join(cat.Modules, ", ")
		}
		rows = append(rows, []string{"MASVS-" + cat.Category, status})
	}
	return table{Headers: []string{"FIELD", "VALUE"}, Rows: rows}
}

func newBuildRegisterCmd(c *CLI) *cobra.Command {
	var manifestFile, appID, buildHash, versionName, profileID string
	var versionCode int64
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a build from a plugin-produced manifest file",
		Long: "Register an immutable build record. Provide --manifest-file (the JSON " +
			"manifest emitted by the Gradle/Xcode build plugins); individual flags override " +
			"manifest fields. The manifest's `manifest` object is stored as build provenance.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			var bm BuildManifest
			if manifestFile != "" {
				data, rerr := os.ReadFile(manifestFile)
				if rerr != nil {
					return fmt.Errorf("read manifest file: %w", rerr)
				}
				if jerr := json.Unmarshal(data, &bm); jerr != nil {
					return newUsageError("parse manifest file: %v", jerr)
				}
			}
			// Flag overrides (only when explicitly set).
			if cmd.Flags().Changed("app-id") {
				bm.AppID = appID
			}
			if cmd.Flags().Changed("build-hash") {
				bm.BuildHash = buildHash
			}
			if cmd.Flags().Changed("version-name") {
				bm.VersionName = versionName
			}
			if cmd.Flags().Changed("version-code") {
				bm.VersionCode = versionCode
			}
			if cmd.Flags().Changed("protection-profile-id") {
				bm.ProtectionProfileID = profileID
			}

			if bm.AppID == "" {
				return newUsageError("app_id is required (in the manifest or via --app-id)")
			}
			if bm.BuildHash == "" {
				return newUsageError("build_hash is required (in the manifest or via --build-hash)")
			}
			manifestStr := ""
			if len(bm.Manifest) > 0 {
				manifestStr = string(bm.Manifest)
			}

			req := &ksealv1.CreateBuildRequest{
				TenantId: tenant, AppId: bm.AppID, BuildHash: bm.BuildHash,
				VersionName: bm.VersionName, VersionCode: bm.VersionCode,
				ProtectionProfileId: bm.ProtectionProfileID, Manifest: manifestStr,
			}
			if c.dryRun {
				c.dryRunNotice("register build " + bm.BuildHash + " for app " + bm.AppID)
				return c.emit(map[string]any{
					"tenant_id": tenant, "app_id": bm.AppID, "build_hash": bm.BuildHash,
					"version_name": bm.VersionName, "version_code": bm.VersionCode,
					"protection_profile_id": bm.ProtectionProfileID,
				}, table{
					Headers: []string{"FIELD", "VALUE"},
					Rows: [][]string{
						{"tenant_id", tenant}, {"app_id", bm.AppID}, {"build_hash", bm.BuildHash},
						{"version_name", bm.VersionName}, {"version_code", strconv.FormatInt(bm.VersionCode, 10)},
						{"protection_profile_id", bm.ProtectionProfileID},
					},
				})
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.registry().CreateBuild(ctx, connect.NewRequest(req))
			if err != nil {
				return err
			}
			b := resp.Msg.GetBuild()
			return c.emit(newBuildView(b), buildTable([]*ksealv1.Build{b}))
		},
	}
	f := cmd.Flags()
	f.StringVar(&manifestFile, "manifest-file", "", "path to the build manifest JSON produced by the build plugins")
	f.StringVar(&appID, "app-id", "", "app id (overrides manifest)")
	f.StringVar(&buildHash, "build-hash", "", "content hash of the protected build (overrides manifest)")
	f.StringVar(&versionName, "version-name", "", "human version name (overrides manifest)")
	f.Int64Var(&versionCode, "version-code", 0, "numeric version code (overrides manifest)")
	f.StringVar(&profileID, "protection-profile-id", "", "protection profile id (overrides manifest)")
	return cmd
}

func newBuildGetCmd(c *CLI) *cobra.Command {
	return &cobra.Command{
		Use:   "get <build-id>",
		Short: "Get a build by id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.registry().GetBuild(ctx, connect.NewRequest(&ksealv1.GetBuildRequest{TenantId: tenant, Id: args[0]}))
			if err != nil {
				return err
			}
			b := resp.Msg.GetBuild()
			return c.emit(newBuildView(b), buildTable([]*ksealv1.Build{b}))
		},
	}
}

func newBuildListCmd(c *CLI) *cobra.Command {
	var appID, pageToken string
	var pageSize int32
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List builds in the tenant (optionally filtered by app)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tenant, err := c.requireTenant()
			if err != nil {
				return err
			}
			ctx, cancel := c.callCtx(cmd.Context())
			defer cancel()
			resp, err := c.registry().ListBuilds(ctx, connect.NewRequest(&ksealv1.ListBuildsRequest{
				TenantId: tenant, AppId: appID, PageSize: pageSize, PageToken: pageToken,
			}))
			if err != nil {
				return err
			}
			bs := resp.Msg.GetBuilds()
			views := make([]buildView, 0, len(bs))
			for _, b := range bs {
				views = append(views, newBuildView(b))
			}
			return c.emit(listJSON("builds", views, resp.Msg.GetNextPageToken()), buildTable(bs))
		},
	}
	cmd.Flags().StringVar(&appID, "app-id", "", "filter by app id")
	cmd.Flags().Int32Var(&pageSize, "page-size", 0, "max results per page")
	cmd.Flags().StringVar(&pageToken, "page-token", "", "pagination token from a previous response")
	return cmd
}
