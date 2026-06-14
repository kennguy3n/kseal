package cli

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// checkStatus is the outcome of a single doctor check.
type checkStatus string

const (
	statusPass checkStatus = "pass"
	statusWarn checkStatus = "warn"
	statusFail checkStatus = "fail"
	statusSkip checkStatus = "skip"
)

// doctorCheck is one diagnostic result. Detail explains what was found; Fix (set
// for warn/fail) tells the developer exactly how to resolve it.
type doctorCheck struct {
	Name   string      `json:"name"`
	Status checkStatus `json:"status"`
	Detail string      `json:"detail"`
	Fix    string      `json:"fix,omitempty"`
}

// doctorReport is the structured projection of a `doctor` run: the resolved
// connection context plus the ordered checks and an overall verdict.
type doctorReport struct {
	Profile  string        `json:"profile"`
	Endpoint string        `json:"endpoint"`
	Tenant   string        `json:"tenant,omitempty"`
	Checks   []doctorCheck `json:"checks"`
	Healthy  bool          `json:"healthy"`
}

// newDoctorCmd implements `kseal doctor`: a guided health check of the whole
// onboarding chain (config → auth → connectivity → app → policy → build proof).
// Each check reports a clear status and an actionable next step, so a developer
// always knows what to do to get their app fully protected.
//
// It is annotated local-only so the root pre-run never aborts on a missing
// endpoint/key; doctor surfaces those as failing checks itself and resolves the
// API key on its own before contacting the server.
func newDoctorCmd(c *CLI) *cobra.Command {
	var strict bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose your setup and show exactly what to do next",
		Long: "Run a sequence of checks across the kseal onboarding path — configuration, API " +
			"key, server connectivity and authentication, tenant scope, app registration, an " +
			"active protection policy, and a registered build proof — and report each with a " +
			"clear status and a concrete next step.\n\n" +
			"doctor never prints secrets and exits non-zero only on hard failures (bad config, " +
			"auth, or an unreachable server). Setup gaps (no app/policy/build yet) are warnings; " +
			"pass --strict to make them fail the command (useful as a CI readiness gate).",
		Example: "  kseal doctor\n" +
			"  kseal doctor --tenant ten_abc123\n" +
			"  kseal doctor --strict --output json",
		Annotations: map[string]string{annotationLocalOnly: "true"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			report, fatal := c.runDoctor(cmd.Context())
			report.Healthy = !report.hasFail() && !(strict && report.hasWarn())

			if c.structured() {
				if err := c.renderStructured(report); err != nil {
					return err
				}
			} else {
				c.printDoctorReport(report)
			}

			if fatal != nil {
				return fatal
			}
			if strict && report.hasWarn() {
				return newBlockedError("doctor found %d setup gap(s); --strict treats them as failures", report.countWarn())
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&strict, "strict", false, "treat setup-gap warnings as failures (exit non-zero)")
	return cmd
}

func (r doctorReport) hasFail() bool  { return r.count(statusFail) > 0 }
func (r doctorReport) hasWarn() bool  { return r.count(statusWarn) > 0 }
func (r doctorReport) countWarn() int { return r.count(statusWarn) }
func (r doctorReport) count(s checkStatus) int {
	n := 0
	for _, ch := range r.Checks {
		if ch.Status == s {
			n++
		}
	}
	return n
}

// runDoctor executes the checks in dependency order, short-circuiting cleanly:
// once a prerequisite fails (no endpoint/key, or the server is unreachable), the
// remaining server-dependent checks are recorded as skipped rather than
// producing confusing cascading errors. It returns the report plus a fatal error
// (typed for exit-code mapping) when a hard failure occurred.
func (c *CLI) runDoctor(ctx context.Context) (doctorReport, error) {
	report := doctorReport{Profile: c.profileName, Endpoint: c.endpoint, Tenant: c.tenant}
	add := func(ch doctorCheck) { report.Checks = append(report.Checks, ch) }

	// 1. Configuration / endpoint (local).
	if c.endpoint == "" {
		add(doctorCheck{Name: "configuration", Status: statusFail,
			Detail: "no server endpoint resolved",
			Fix:    fmt.Sprintf("run `kseal init`, pass --endpoint, or set $%s", endpointEnvVar)})
		skipServerChecks(&report, "no endpoint")
		return report, withHint(newUsageError("no endpoint configured"),
			"run `kseal init` to create a connection profile")
	}
	add(doctorCheck{Name: "configuration", Status: statusPass,
		Detail: fmt.Sprintf("profile %q → %s", c.profileName, c.endpoint)})

	// 2. Credentials (local) — resolve without exposing the key value.
	key, keyErr := c.profile.resolveAPIKey()
	if keyErr != nil {
		add(doctorCheck{Name: "credentials", Status: statusFail,
			Detail: "API key not found",
			Fix:    fmt.Sprintf("export $%s with your tenant API key (read at runtime, never stored)", c.profile.apiKeyEnvName())})
		skipServerChecks(&report, "no API key")
		return report, keyErr
	}
	c.apiKey = key
	add(doctorCheck{Name: "credentials", Status: statusPass,
		Detail: fmt.Sprintf("API key resolved from $%s", c.profile.apiKeyEnvName())})

	// 3. Connectivity + authentication. ListTenants is the lightest authenticated
	// control-plane call; it confirms the server is reachable and the key is valid.
	connCtx, cancel := c.callCtx(ctx)
	_, connErr := c.registry().ListTenants(connCtx, connect.NewRequest(&ksealv1.ListTenantsRequest{PageSize: 1}))
	cancel()
	if connErr != nil {
		fix := "check the endpoint and your network"
		switch connect.CodeOf(connErr) {
		case connect.CodeUnauthenticated, connect.CodePermissionDenied:
			fix = fmt.Sprintf("the API key in $%s was rejected; rotate or replace it in the console", c.profile.apiKeyEnvName())
		case connect.CodeUnavailable, connect.CodeDeadlineExceeded:
			fix = "the server is unreachable; verify the endpoint URL and that the service is up"
		}
		add(doctorCheck{Name: "connectivity", Status: statusFail,
			Detail: fmt.Sprintf("control-plane call failed: %v", connErr), Fix: fix})
		skipServerChecks(&report, "server unreachable")
		return report, connErr
	}
	add(doctorCheck{Name: "connectivity", Status: statusPass,
		Detail: "reached the control plane and authenticated"})

	// 4. Tenant scope.
	if c.tenant == "" {
		add(doctorCheck{Name: "tenant-scope", Status: statusWarn,
			Detail: "no default tenant set",
			Fix:    "set one with `kseal config set-profile --name " + c.profileName + " --tenant-id <id>` so commands need no --tenant"})
		// App/policy/build checks are tenant-scoped; skip them with guidance.
		add(doctorCheck{Name: "app-registration", Status: statusSkip, Detail: "skipped: no tenant scope"})
		add(doctorCheck{Name: "protection-policy", Status: statusSkip, Detail: "skipped: no tenant scope"})
		add(doctorCheck{Name: "build-proof", Status: statusSkip, Detail: "skipped: no tenant scope"})
		return report, nil
	}
	add(doctorCheck{Name: "tenant-scope", Status: statusPass, Detail: "tenant " + c.tenant})

	// 5. App registration.
	apps := c.doctorApps(ctx, add)

	// 6. Protection policy (only meaningful once an app exists).
	c.doctorPolicy(ctx, apps, add)

	// 7. Build proof.
	c.doctorBuilds(ctx, add)

	return report, nil
}

// doctorApps checks whether any app is registered in the tenant and returns the
// app list for downstream policy inspection.
func (c *CLI) doctorApps(ctx context.Context, add func(doctorCheck)) []*ksealv1.App {
	callCtx, cancel := c.callCtx(ctx)
	resp, err := c.registry().ListApps(callCtx, connect.NewRequest(&ksealv1.ListAppsRequest{TenantId: c.tenant, PageSize: 50}))
	cancel()
	if err != nil {
		add(doctorCheck{Name: "app-registration", Status: statusWarn,
			Detail: fmt.Sprintf("could not list apps: %v", err),
			Fix:    "retry, or register an app with `kseal app create`"})
		return nil
	}
	apps := resp.Msg.GetApps()
	if len(apps) == 0 {
		add(doctorCheck{Name: "app-registration", Status: statusWarn,
			Detail: "no apps registered in this tenant",
			Fix:    "register one with `kseal app create --name \"My App\" --platform android --package-id com.example.app` — the unit kseal protects"})
		return nil
	}
	add(doctorCheck{Name: "app-registration", Status: statusPass,
		Detail: fmt.Sprintf("%d app(s) registered", len(apps))})
	return apps
}

// doctorPolicy reports whether the apps are protected by an active enforcement
// policy. A tenant-wide policy or any per-app active policy counts as protected.
func (c *CLI) doctorPolicy(ctx context.Context, apps []*ksealv1.App, add func(doctorCheck)) {
	if len(apps) == 0 {
		add(doctorCheck{Name: "protection-policy", Status: statusSkip,
			Detail: "skipped: register an app first"})
		return
	}
	protected := 0
	enforcing := 0
	for _, app := range apps {
		callCtx, cancel := c.callCtx(ctx)
		resp, err := c.registry().GetActivePolicy(callCtx, connect.NewRequest(&ksealv1.GetActivePolicyRequest{TenantId: c.tenant, AppId: app.GetId()}))
		cancel()
		if err != nil {
			if connect.CodeOf(err) == connect.CodeNotFound {
				continue
			}
			add(doctorCheck{Name: "protection-policy", Status: statusWarn,
				Detail: fmt.Sprintf("could not resolve active policy for %s: %v", app.GetId(), err)})
			return
		}
		pol := resp.Msg.GetPolicy()
		if pol == nil {
			continue
		}
		protected++
		if pol.GetEnforcementMode() != ksealv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE {
			enforcing++
		}
	}
	switch {
	case protected == 0:
		add(doctorCheck{Name: "protection-policy", Status: statusWarn,
			Detail: "no app has an active policy",
			Fix:    "apply a curated baseline with `kseal policy pack apply <pack> --app-id <app-id> --activate`"})
	case enforcing == 0:
		add(doctorCheck{Name: "protection-policy", Status: statusWarn,
			Detail: fmt.Sprintf("%d app(s) have an active policy, all in observe mode", protected),
			Fix:    "move to step_up or block once you trust the signals (edit the policy's enforcement_mode)"})
	default:
		add(doctorCheck{Name: "protection-policy", Status: statusPass,
			Detail: fmt.Sprintf("%d app(s) protected, %d actively enforcing", protected, enforcing)})
	}
}

// doctorBuilds reports whether at least one protected build is registered, which
// establishes the build proof the runtime verifies in the field.
func (c *CLI) doctorBuilds(ctx context.Context, add func(doctorCheck)) {
	callCtx, cancel := c.callCtx(ctx)
	resp, err := c.registry().ListBuilds(callCtx, connect.NewRequest(&ksealv1.ListBuildsRequest{TenantId: c.tenant, PageSize: 1}))
	cancel()
	if err != nil {
		add(doctorCheck{Name: "build-proof", Status: statusWarn,
			Detail: fmt.Sprintf("could not list builds: %v", err)})
		return
	}
	if len(resp.Msg.GetBuilds()) == 0 {
		add(doctorCheck{Name: "build-proof", Status: statusWarn,
			Detail: "no protected build registered yet",
			Fix:    "produce a hardened build with the Gradle/Xcode plugin, then `kseal build register --manifest-file <file>`"})
		return
	}
	add(doctorCheck{Name: "build-proof", Status: statusPass,
		Detail: "at least one protected build is registered"})
}

// skipServerChecks records the remaining server-dependent checks as skipped with
// a shared reason, used when a prerequisite (endpoint/key/connectivity) failed.
// Checks already recorded (e.g. a connectivity FAIL) are left untouched so the
// report never carries a duplicate entry for the same check.
func skipServerChecks(report *doctorReport, reason string) {
	present := make(map[string]bool, len(report.Checks))
	for _, ch := range report.Checks {
		present[ch.Name] = true
	}
	for _, name := range []string{"connectivity", "tenant-scope", "app-registration", "protection-policy", "build-proof"} {
		if present[name] {
			continue
		}
		report.Checks = append(report.Checks, doctorCheck{Name: name, Status: statusSkip, Detail: "skipped: " + reason})
	}
}

// printDoctorReport renders the human-friendly doctor table plus a one-line
// verdict and the highest-priority fixes.
func (c *CLI) printDoctorReport(r doctorReport) {
	tbl := table{Headers: []string{"CHECK", "STATUS", "DETAIL"}}
	for _, ch := range r.Checks {
		tbl.Rows = append(tbl.Rows, []string{ch.Name, statusLabel(ch.Status), ch.Detail})
	}
	_ = tbl.render(c.out)
	fmt.Fprintln(c.out)

	// Surface the fixes for anything not passing, in order.
	var fixes []doctorCheck
	for _, ch := range r.Checks {
		if (ch.Status == statusWarn || ch.Status == statusFail) && ch.Fix != "" {
			fixes = append(fixes, ch)
		}
	}
	if len(fixes) > 0 {
		fmt.Fprintln(c.out, "What to do next:")
		for _, ch := range fixes {
			fmt.Fprintf(c.out, "  - [%s] %s\n", ch.Name, ch.Fix)
		}
		fmt.Fprintln(c.out)
	}
	if r.Healthy {
		fmt.Fprintln(c.out, "All good — your setup is healthy.")
	} else {
		fmt.Fprintf(c.out, "Setup needs attention: %d failing, %d warning.\n", r.count(statusFail), r.count(statusWarn))
	}
}

// statusLabel renders a status as an uppercase, padding-free token for the table.
func statusLabel(s checkStatus) string {
	switch s {
	case statusPass:
		return "PASS"
	case statusWarn:
		return "WARN"
	case statusFail:
		return "FAIL"
	default:
		return "SKIP"
	}
}
