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
	debug      bool
	timeout    time.Duration
}

// Execute builds the root command and runs it, returning a process exit code.
// main() is a thin wrapper around this so the whole CLI is testable in-process.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	root, gf := newRootCmd(stdout, stderr)
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.ExecuteContext(ctx)
	if err != nil {
		renderError(stderr, err, gf.debug)
		return ExitCode(err)
	}
	return ExitOK
}

func newRootCmd(stdout, stderr io.Writer) (*cobra.Command, *globalFlags) {
	gf := &globalFlags{}
	c := &CLI{out: stdout, errOut: stderr, in: os.Stdin}

	root := &cobra.Command{
		Use:   "kseal",
		Short: "Scriptable operator CLI for the kseal continuous app-trust platform",
		Long: "kseal manages tenants, apps, builds, policies, protection profiles, " +
			"webhooks, and event queries over the kseal Connect APIs.\n\n" +
			"It is built for NoOps/self-service: every mutating command supports --dry-run, " +
			"results render as --output table|json|yaml, exit codes are stable for CI, and the " +
			"API key is read from the environment or a secret file (never stored or printed).\n\n" +
			"New here? Run `kseal init` for a guided setup, then `kseal doctor` to check that " +
			"your app is wired up and protected.",
		Example: "  # Guided first-run setup, then verify your setup\n" +
			"  kseal init\n" +
			"  kseal doctor\n\n" +
			"  # Register an app and apply a curated baseline policy\n" +
			"  kseal app create --name \"Acme Wallet\" --platform android --package-id com.acme.wallet\n" +
			"  kseal policy pack apply fintech --app-id <app-id> --activate\n\n" +
			"  # Script-friendly machine output\n" +
			"  kseal tenant list --output json | jq '.tenants[].id'\n" +
			"  kseal app list --output yaml",
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
	pf.StringVar(&gf.profile, "profile", "", "connection profile to use (flag > $KSEAL_PROFILE > current profile)")
	pf.StringVar(&gf.endpoint, "endpoint", "", "server base URL (flag > $KSEAL_ENDPOINT > profile endpoint)")
	pf.StringVar(&gf.tenant, "tenant", "", "tenant id scope (flag > $KSEAL_TENANT > profile tenant)")
	pf.StringVarP(&gf.output, "output", "o", "", "output format: table|json|yaml (flag > $KSEAL_OUTPUT > table)")
	pf.BoolVar(&gf.dryRun, "dry-run", false, "print the request that would be sent without performing any mutation")
	pf.BoolVar(&gf.debug, "debug", false, "print verbose diagnostics (full error chain, exit code) to stderr")
	pf.DurationVar(&gf.timeout, "timeout", 30*time.Second, "per-request timeout (0 = no timeout)")

	// Offer the supported formats as shell-completion candidates for --output.
	_ = root.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return outputFormats, cobra.ShellCompDirectiveNoFileComp
	})

	root.AddCommand(
		newInitCmd(c, gf),
		newDoctorCmd(c),
		newConfigCmd(c),
		newTenantCmd(c),
		newAppCmd(c),
		newBuildCmd(c),
		newPolicyCmd(c),
		newProfileCmd(c),
		newWebhookCmd(c),
		newEventsCmd(c),
		newComplianceCmd(c),
		newManCmd(c),
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

	// Profile selection precedence: --profile flag > $KSEAL_PROFILE > config
	// CurrentProfile > synthesized "default".
	profileName := firstNonEmpty(gf.profile, os.Getenv(profileEnvVar))
	name, prof, err := cfg.ResolveProfile(profileName)
	if err != nil {
		return err
	}
	c.profileName = name
	c.profile = prof

	// Per-setting precedence: flag > environment > profile. Keeping the chain
	// explicit (rather than a generic lookup) documents the contract and lets
	// each setting fall back independently.
	c.endpoint = firstNonEmpty(gf.endpoint, os.Getenv(endpointEnvVar), prof.Endpoint)
	c.tenant = firstNonEmpty(gf.tenant, os.Getenv(tenantEnvVar), prof.Tenant)

	out, err := parseOutputFormat(firstNonEmpty(gf.output, os.Getenv(outputEnvVar)))
	if err != nil {
		return newUsageError("%v", err)
	}
	c.output = out
	c.dryRun = gf.dryRun
	c.debug = gf.debug
	c.timeout = gf.timeout

	// Commands that talk to the server need an endpoint + API key. Config
	// management commands ("config ...") do not, so skip resolution for them.
	if commandNeedsServer(cmd) {
		if c.endpoint == "" {
			return withHint(
				newUsageError("no endpoint configured"),
				"pass --endpoint <url>, set $%s, or run `kseal init` to create a profile.",
				endpointEnvVar,
			)
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
	// A non-runnable command (no Run/RunE — e.g. a bare group such as
	// "kseal policy" or the root itself) only prints help and never reaches
	// the server, so it must not demand an endpoint or API key.
	if !cmd.Runnable() {
		return false
	}
	for c := cmd; c != nil; c = c.Parent() {
		if c.Annotations[annotationLocalOnly] == "true" {
			return false
		}
		// Cobra's built-in helpers (shell completion, hidden __complete*, and
		// help) are offline by definition; they must run without credentials.
		if isLocalBuiltin(c) {
			return false
		}
	}
	return true
}

// isLocalBuiltin reports whether cmd is one of cobra's generated, credential-free
// helper commands (the `completion` subtree, dynamic `__complete*` shells, or
// `help`). These never contact the server.
func isLocalBuiltin(cmd *cobra.Command) bool {
	switch cmd.Name() {
	case "completion", "help",
		cobra.ShellCompRequestCmd, cobra.ShellCompNoDescRequestCmd:
		return true
	}
	return false
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
