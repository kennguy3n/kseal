// Package cli implements kseal-cli: a scriptable operator CLI over the kseal
// Connect APIs. It is CI-friendly (stable exit codes, --output json, --dry-run
// on every mutating command), strictly tenant-scoped, and never prints or
// stores secret values.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// version is overridable at build time via -ldflags "-X ...cli.version=...".
var version = "dev"

// global flag values, bound on the root command.
type globalFlags struct {
	configPath string
	profile    string
	endpoint   string
	tenant     string
	output     string
	dryRun     bool
	timeout    time.Duration
}

// Execute builds the root command and runs it, returning a process exit code.
// main() is a thin wrapper around this so the whole CLI is testable in-process.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	root, gf := newRootCmd(stdout, stderr)
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	_ = gf
	err := root.ExecuteContext(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return ExitCode(err)
	}
	return ExitOK
}

func newRootCmd(stdout, stderr io.Writer) (*cobra.Command, *globalFlags) {
	gf := &globalFlags{}
	c := &CLI{out: stdout, errOut: stderr}

	root := &cobra.Command{
		Use:   "kseal-cli",
		Short: "Scriptable operator CLI for the kseal continuous app-trust platform",
		Long: "kseal-cli manages tenants, apps, builds, policies, protection profiles, " +
			"webhooks, and event queries over the kseal Connect APIs.\n\n" +
			"It is built for NoOps/self-service: every mutating command supports --dry-run, " +
			"results render as --output table|json, exit codes are stable for CI, and the API " +
			"key is read from the environment or a secret file (never stored or printed).",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		// Resolve config + profile + effective settings before any subcommand
		// (except those that don't need a server/profile, handled per-command).
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return c.init(gf, cmd)
		},
	}

	pf := root.PersistentFlags()
	pf.StringVar(&gf.configPath, "config", "", "config file path (default: $KSEAL_CONFIG or ~/.config/kseal/config.json)")
	pf.StringVar(&gf.profile, "profile", "", "connection profile to use (default: current profile)")
	pf.StringVar(&gf.endpoint, "endpoint", "", "server base URL (overrides the profile endpoint)")
	pf.StringVar(&gf.tenant, "tenant", "", "tenant id scope (overrides the profile tenant)")
	pf.StringVarP(&gf.output, "output", "o", "table", "output format: table|json")
	pf.BoolVar(&gf.dryRun, "dry-run", false, "print the request that would be sent without performing any mutation")
	pf.DurationVar(&gf.timeout, "timeout", 30*time.Second, "per-request timeout (0 = no timeout)")

	root.AddCommand(
		newConfigCmd(c),
		newTenantCmd(c),
		newAppCmd(c),
		newBuildCmd(c),
		newPolicyCmd(c),
		newProfileCmd(c),
		newWebhookCmd(c),
		newEventsCmd(c),
	)
	return root, gf
}

// init resolves the effective runtime configuration from flags + config file.
func (c *CLI) init(gf *globalFlags, cmd *cobra.Command) error {
	path := gf.configPath
	if path == "" {
		p, err := DefaultConfigPath()
		if err != nil {
			return err
		}
		path = p
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		return err
	}
	c.cfg = cfg
	c.configPathResolved = path

	name, prof, err := cfg.ResolveProfile(gf.profile)
	if err != nil {
		return err
	}
	c.profileName = name
	c.profile = prof

	c.endpoint = prof.Endpoint
	if gf.endpoint != "" {
		c.endpoint = gf.endpoint
	}
	c.tenant = prof.Tenant
	if gf.tenant != "" {
		c.tenant = gf.tenant
	}

	out, err := parseOutputFormat(gf.output)
	if err != nil {
		return newUsageError("%v", err)
	}
	c.output = out
	c.dryRun = gf.dryRun
	c.timeout = gf.timeout

	// Commands that talk to the server need an endpoint + API key. Config
	// management commands ("config ...") do not, so skip resolution for them.
	if commandNeedsServer(cmd) {
		if c.endpoint == "" {
			return newUsageError("no endpoint configured: set one on the profile or pass --endpoint")
		}
		key, err := c.profile.resolveAPIKey()
		if err != nil {
			return err
		}
		c.apiKey = key
	}
	return nil
}

// annotationLocalOnly marks a command (or command subtree) as purely local:
// it makes no server calls, so endpoint/API-key resolution is skipped. This
// keeps offline commands (e.g. the "config" tree and "policy validate") usable
// in CI without credentials. It is set on the parent command and inherited by
// the whole subtree via commandNeedsServer's walk to the root.
const annotationLocalOnly = "kseal/local-only"

// commandNeedsServer reports whether the command makes server calls. A command
// is local-only if it (or any ancestor) carries annotationLocalOnly.
func commandNeedsServer(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		if c.Annotations[annotationLocalOnly] == "true" {
			return false
		}
	}
	return true
}

// dryRunNotice prints a standard dry-run banner to stderr.
func (c *CLI) dryRunNotice(action string) {
	fmt.Fprintf(c.errOut, "dry-run: would %s (no changes made)\n", action)
}

func init() {
	// Cobra prints its own usage on flag errors; keep output deterministic.
	cobra.EnableCommandSorting = false
	_ = os.Stdout
}
