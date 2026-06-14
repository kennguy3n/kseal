package cli

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

// nextStep is a single recommended action surfaced after `init` (and by
// `doctor`). It pairs the command to run with a short rationale so a developer
// understands *why* the step makes their app more secure, not just what to type.
type nextStep struct {
	Title   string `json:"title"`
	Command string `json:"command"`
	Why     string `json:"why"`
}

// initResult is the structured projection of a completed `init`. It echoes the
// saved profile (never the key value) plus the guided next steps so the flow is
// scriptable and its guidance is machine-readable.
type initResult struct {
	Profile   string     `json:"profile"`
	Current   bool       `json:"current"`
	Endpoint  string     `json:"endpoint"`
	Tenant    string     `json:"tenant,omitempty"`
	APIKeyEnv string     `json:"api_key_env"`
	APIKeySet bool       `json:"api_key_set"`
	NextSteps []nextStep `json:"next_steps"`
}

// newInitCmd implements the guided onboarding flow. It is local-only: it writes
// a connection profile and prints a "get secure fast" path. When run on a TTY
// with values missing it prompts; with all values supplied (or --non-interactive)
// it is fully scriptable, so the same command works in a developer shell and in
// CI bootstrap.
func newInitCmd(c *CLI, gf *globalFlags) *cobra.Command {
	var (
		name           string
		endpoint       string
		tenant         string
		apiKeyEnv      string
		apiKeyFile     string
		nonInteractive bool
		noUse          bool
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Guided first-run setup: create a connection profile and learn the secure path",
		Long: "Set up kseal for self-service in one step. `init` creates (or updates) a named " +
			"connection profile — endpoint, default tenant, and where to read the API key from — " +
			"and then prints a short, ordered path to get your app protected.\n\n" +
			"The API key value is never stored or printed: the profile records only the name of " +
			"the environment variable (default KSEAL_API_KEY) or a file path to read it from at " +
			"runtime. On a terminal, missing values are prompted for; pass them as flags (or use " +
			"--non-interactive) to script the setup in CI.",
		Example: "  # Interactive on a terminal\n" +
			"  kseal init\n\n" +
			"  # Fully scripted (CI bootstrap)\n" +
			"  kseal init --name prod --endpoint https://api.kseal.example.com \\\n" +
			"    --tenant-id ten_abc123 --non-interactive\n\n" +
			"  # Preview without writing anything\n" +
			"  kseal init --name prod --endpoint https://api.kseal.example.com --dry-run",
		Annotations: map[string]string{annotationLocalOnly: "true"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			interactive := !nonInteractive && c.isInteractive()

			// Seed from the existing active profile so re-running init edits in
			// place rather than clobbering settings the developer already has.
			if name == "" {
				name = firstNonEmpty(c.profileName, defaultProfile)
			}
			existing := c.cfg.Profiles[name]
			if endpoint == "" && existing != nil {
				endpoint = existing.Endpoint
			}
			if tenant == "" && existing != nil {
				tenant = existing.Tenant
			}
			if apiKeyEnv == "" && existing != nil {
				apiKeyEnv = existing.APIKeyEnv
			}
			if apiKeyFile == "" && existing != nil {
				apiKeyFile = existing.APIKeyFile
			}

			if interactive {
				fmt.Fprintln(c.errOut, "Welcome to kseal. Let's connect this machine to your tenant.")
				fmt.Fprintln(c.errOut, "Press Enter to accept the [default] shown for each prompt.")
				fmt.Fprintln(c.errOut)
				name = c.prompt("Profile name", firstNonEmpty(name, defaultProfile))
				endpoint = c.prompt("Server endpoint", firstNonEmpty(endpoint, defaultEndpoint))
				tenant = c.prompt("Default tenant id (optional, recommended)", tenant)
				apiKeyEnv = c.prompt("Environment variable holding the API key", firstNonEmpty(apiKeyEnv, defaultAPIKeyEnv))
			}

			if name == "" {
				name = defaultProfile
			}
			if endpoint == "" {
				endpoint = defaultEndpoint
			}
			if apiKeyEnv == "" {
				apiKeyEnv = defaultAPIKeyEnv
			}

			prof := &Profile{
				Endpoint:   endpoint,
				Tenant:     tenant,
				APIKeyEnv:  apiKeyEnv,
				APIKeyFile: apiKeyFile,
			}
			makeCurrent := !noUse

			if c.dryRun {
				c.dryRunNotice(fmt.Sprintf("write profile %q (endpoint=%s) to %s", name, endpoint, c.configPathResolved))
			} else {
				c.cfg.Profiles[name] = prof
				if makeCurrent || c.cfg.CurrentProfile == "" {
					c.cfg.CurrentProfile = name
				}
				if err := c.cfg.Save(c.configPathResolved); err != nil {
					return err
				}
			}

			keySet := prof.resolveAPIKeyAvailable()
			res := initResult{
				Profile:   name,
				Current:   makeCurrent || c.cfg.CurrentProfile == name,
				Endpoint:  endpoint,
				Tenant:    tenant,
				APIKeyEnv: prof.apiKeyEnvName(),
				APIKeySet: keySet,
				NextSteps: onboardingSteps(tenant, prof.apiKeyEnvName(), keySet),
			}

			if c.structured() {
				return c.renderStructured(res)
			}
			c.printInitSummary(res)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&name, "name", "", "profile name to create or update (default: current profile or \"default\")")
	f.StringVar(&endpoint, "endpoint", "", "server base URL")
	f.StringVar(&tenant, "tenant-id", "", "default tenant id for this profile")
	f.StringVar(&apiKeyEnv, "api-key-env", "", "environment variable to read the API key from (default KSEAL_API_KEY)")
	f.StringVar(&apiKeyFile, "api-key-file", "", "file to read the API key from when the env var is unset")
	f.BoolVar(&nonInteractive, "non-interactive", false, "never prompt; use flags and defaults only (for CI)")
	f.BoolVar(&noUse, "no-use", false, "do not set the created profile as the current profile")
	return cmd
}

// onboardingSteps returns the ordered "get secure fast" path, tailored to what
// the developer has already configured so the very next action is always the
// most useful one.
func onboardingSteps(tenant, apiKeyEnv string, keySet bool) []nextStep {
	if apiKeyEnv == "" {
		apiKeyEnv = defaultAPIKeyEnv
	}
	steps := make([]nextStep, 0, 5)
	if !keySet {
		steps = append(steps, nextStep{
			Title:   "Provide your API key",
			Command: "export " + apiKeyEnv + "=<your-key>",
			Why:     "Every control-plane call is authenticated with a tenant-scoped key. It is read at runtime and never stored on disk.",
		})
	}
	steps = append(steps, nextStep{
		Title:   "Verify your setup",
		Command: "kseal doctor",
		Why:     "Confirms connectivity, auth, and whether your app is registered and protected before you ship anything.",
	})
	appScope := "--app-id <app-id>"
	if tenant == "" {
		steps = append(steps, nextStep{
			Title:   "Register an app",
			Command: "kseal --tenant <id> app create --name \"My App\" --platform android --package-id com.example.app",
			Why:     "Apps are the unit kseal protects. Registering one lets the build plugins and runtime SDK bind to a known identity.",
		})
	} else {
		steps = append(steps, nextStep{
			Title:   "Register an app",
			Command: "kseal app create --name \"My App\" --platform android --package-id com.example.app",
			Why:     "Apps are the unit kseal protects. Registering one lets the build plugins and runtime SDK bind to a known identity.",
		})
	}
	steps = append(steps,
		nextStep{
			Title:   "Apply a curated baseline policy",
			Command: "kseal policy pack apply fintech " + appScope + " --activate",
			Why:     "Vertical packs ship sensible enforcement defaults, so you start protected without authoring rules by hand.",
		},
		nextStep{
			Title:   "Register your first protected build",
			Command: "kseal build register --manifest-file ./build/kseal-manifest.json",
			Why:     "Recording the build hash establishes the build proof the runtime uses to verify integrity in the field.",
		},
	)
	return steps
}

// printInitSummary renders the human-friendly result of init: a confirmation
// line, a no-secrets profile recap, and the numbered secure path.
func (c *CLI) printInitSummary(res initResult) {
	fmt.Fprintf(c.out, "Profile %q saved", res.Profile)
	if res.Current {
		fmt.Fprint(c.out, " and set as current")
	}
	fmt.Fprintln(c.out, ".")
	fmt.Fprintln(c.out)
	recap := table{Headers: []string{"SETTING", "VALUE"}, Rows: [][]string{
		{"endpoint", res.Endpoint},
		{"tenant", emptyDash(res.Tenant)},
		{"api_key_env", res.APIKeyEnv},
		{"api_key_set", yesNo(res.APIKeySet)},
	}}
	_ = recap.render(c.out)
	fmt.Fprintln(c.out)
	fmt.Fprintln(c.out, "Next steps to get secure fast:")
	for i, s := range res.NextSteps {
		fmt.Fprintf(c.out, "  %d. %s\n", i+1, s.Title)
		fmt.Fprintf(c.out, "     $ %s\n", s.Command)
		fmt.Fprintf(c.out, "     %s\n", s.Why)
	}
}

// isInteractive reports whether prompting is appropriate: input is available
// and connected to a terminal. It is false under test, in pipes, and in CI, so
// non-interactive callers never block on a prompt.
func (c *CLI) isInteractive() bool {
	f, ok := c.in.(interface{ Fd() uintptr })
	if !ok {
		return false
	}
	return isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
}

// prompt asks a single question with an optional default, returning the trimmed
// answer or the default on empty input.
func (c *CLI) prompt(label, def string) string {
	if def != "" {
		fmt.Fprintf(c.errOut, "%s [%s]: ", label, def)
	} else {
		fmt.Fprintf(c.errOut, "%s: ", label)
	}
	reader := bufio.NewReader(c.in)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
