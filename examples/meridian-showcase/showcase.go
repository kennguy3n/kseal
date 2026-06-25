package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/kseal/server/control-plane/compliance"
	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/data-plane/siem"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// Device/wire risk-bit positions (RiskBitset layout, mirrored from
// server/shared/risk and sdk/rust-core/kseal-core/src/risk.rs). The server
// translates these through FromWire before scoring, so a telemetry event's
// risk level is derived from exactly these bits.
const (
	wRoot          = 0
	wJailbreak     = 1
	wEmulator      = 2
	wDebugger      = 4
	wHooking       = 5
	wTamper        = 6
	wAppIntegrity  = 7
	wNetworkMITM   = 8
	wEnvironment   = 9
	wProxy         = 10
	wUserCA        = 11
	wAttestFail    = 13
	wScreenCapture = 16
	wOverlay       = 17
	wAccessibility = 18
	wMaliciousIME  = 19
	wRemoteAccess  = 20
)

func bits(positions ...int) uint64 {
	var b uint64
	for _, p := range positions {
		b |= uint64(1) << uint(p)
	}
	return b
}

// policyHash matches docs/reference/fixtures/control/policy.json
// (= sha256("meridian/payments-baseline/v12")) so every event ties back to the
// exact policy the docs describe.
const policyHash = "62fdc9b7f2da819931d88affe6ca7c3c22fcbbf0aeb2077a68994a1d4f508c34"

// canonical module sets.
var (
	// buildModules normalize (lower-case, strip non-alphanumerics) onto the
	// console's MASVS module map, so the MASVS evidence view reports full
	// category coverage from the registered build manifest.
	buildModules = []string{
		"app_integrity", "rasp", "attestation", "api_attestation",
		"network", "tls", "obfuscation", "anti_hooking",
		"environment", "root", "jailbreak", "storage", "crypto", "privacy",
	}
	buildTransforms = []string{
		"control-flow-flattening", "mixed-boolean-arithmetic",
		"string-obfuscation", "native-symbol-encryption",
	}
	// policyModules are the 14 RASP probes shown on the Policies view, matching
	// docs/reference/fixtures/control/policy.json.
	policyModules = []string{
		"app_integrity", "runtime_tamper", "debugger", "hooking",
		"environment", "network", "request_proof", "secret_protection",
		"privacy_guard", "screen_capture", "overlay", "accessibility",
		"malicious_ime", "remote_access",
	}
)

type manifest struct {
	Modules             []string `json:"modules"`
	Transforms          []string `json:"transforms"`
	Version             string   `json:"version"`
	ObfuscationStrength string   `json:"obfuscation_strength"`
}

func buildManifest(version, strength string) string {
	return mustJSON(manifest{
		Modules:             buildModules,
		Transforms:          buildTransforms,
		Version:             version,
		ObfuscationStrength: strength,
	})
}

// appSeed is the registry result for one app threaded through the later steps.
type appSeed struct {
	app           *ksealv1.App
	currentBuild  string // build hash of the latest build
	repackedBuild string // a malicious build hash for the kill switch
	builds        []*ksealv1.Build
}

func (s *seeder) run() error {
	ctx := s.ctx

	// 1. Tenant.
	tenant, err := s.store.CreateTenant(ctx, registry.CreateTenantInput{
		Name: "Meridian Pay",
		Slug: "meridian",
		Tier: "enterprise",
	})
	if err != nil {
		return fmt.Errorf("create tenant (run `make clean && make up` for a fresh DB if this is a conflict): %w", err)
	}
	log.Printf("tenant: %s (%s)", tenant.Id, tenant.Slug)

	// 2. Tenant signing key (signs policy config and kill switches).
	if _, err := s.store.CreateSigningKey(ctx, tenant.Id); err != nil {
		return fmt.Errorf("create signing key: %w", err)
	}

	// 3. Apps + builds + protection profiles.
	pay, err := s.seedApp(tenant.Id, appSpec{
		name:      "pay-android",
		platform:  ksealv1.Platform_PLATFORM_ANDROID,
		packageID: "com.meridianpay.wallet",
		signers:   []string{"SHA256:6f:2c:9b:meridian-wallet-release"},
		profile:   "payments-android-hardened",
		builds: []buildSpec{
			{version: "4.2.0", code: 420, strength: "OBFUSCATION_STRENGTH_HIGH"},
			{version: "4.1.3", code: 413, strength: "OBFUSCATION_STRENGTH_HIGH"},
			{version: "4.1.0", code: 410, strength: "OBFUSCATION_STRENGTH_MEDIUM"},
		},
		repacked: "4.2.0-repack",
	})
	if err != nil {
		return err
	}

	merchant, err := s.seedApp(tenant.Id, appSpec{
		name:      "merchant",
		platform:  ksealv1.Platform_PLATFORM_ANDROID,
		packageID: "com.meridianpay.merchant",
		signers:   []string{"SHA256:a1:44:ef:meridian-merchant-release"},
		profile:   "merchant-android-hardened",
		builds: []buildSpec{
			{version: "2.8.0", code: 280, strength: "OBFUSCATION_STRENGTH_HIGH"},
			{version: "2.7.1", code: 271, strength: "OBFUSCATION_STRENGTH_MEDIUM"},
		},
		repacked: "2.8.0-repack",
	})
	if err != nil {
		return err
	}

	// 4. Policies (baseline active + a tighter candidate for the canary).
	baseline, err := s.seedPolicy(tenant.Id, pay.app.Id, "payments-baseline",
		thresholds{130, 90, 50, 20}, true)
	if err != nil {
		return err
	}
	candidate, err := s.seedPolicy(tenant.Id, pay.app.Id, "payments-canary-tighter",
		thresholds{120, 80, 45, 18}, false)
	if err != nil {
		return err
	}
	if _, err := s.seedPolicy(tenant.Id, merchant.app.Id, "merchant-baseline",
		thresholds{130, 90, 50, 20}, true); err != nil {
		return err
	}

	// 5. API key for console login (and telemetry submission until SDK device
	// credentials are implemented). Include every read scope the console pages
	// use so the showcase can be navigated end-to-end without auth errors.
	apiKey, _, err := s.store.CreateAPIKey(ctx, tenant.Id, "soc-console",
		[]string{
			"control:read", "control:write",
			"data:read",
			"query:read",
			"registry:read",
			"policy:read",
			"compliance:read",
		})
	if err != nil {
		return fmt.Errorf("create api key: %w", err)
	}
	s.apiKey = apiKey

	// 6. Webhooks.
	if err := s.seedWebhooks(tenant.Id); err != nil {
		return err
	}

	// 7. SIEM connector (Splunk HEC).
	if err := s.seedSIEM(tenant.Id); err != nil {
		return err
	}

	// 8. Data-processing registry.
	if err := s.seedDataProcessing(tenant.Id, pay.app.Id, merchant.app.Id); err != nil {
		return err
	}

	// 9. Audit trail (hash-chained; appended sequentially).
	if err := s.seedAudit(tenant.Id, pay, merchant); err != nil {
		return err
	}

	// 10. Kill switches (one armed DISABLE for a repackaged build; one ENABLE).
	if err := s.seedKillSwitches(tenant.Id, pay, merchant); err != nil {
		return err
	}

	// 11. Canary rollout for pay-android.
	if _, err := s.comp.SetCanary(ctx, compliance.CanaryInput{
		TenantID:          tenant.Id,
		AppID:             pay.app.Id,
		CandidatePolicyID: candidate.Id,
		Percent:           25,
		RollbackThreshold: 0.05,
	}); err != nil {
		return fmt.Errorf("set canary: %w", err)
	}
	log.Printf("canary: pay-android candidate %q at 25%% (stable %q)", candidate.Name, baseline.Name)

	// 12. Trust sessions (drives the dashboard trust-level distribution).
	if err := s.seedTrustSessions(tenant.Id, pay, merchant); err != nil {
		return err
	}

	// 13. Telemetry events over the public ingest API.
	if err := s.ingestEvents(tenant.Id, pay); err != nil {
		return err
	}
	if err := s.ingestEvents(tenant.Id, merchant); err != nil {
		return err
	}

	s.printSummary(tenant, apiKey, pay, merchant)
	return nil
}

// currentBuildHashes maps each app's package ID to the build hash of its latest
// build — identical to the hash the full seed assigns in seedApp, so re-ingested
// events tie back to the same builds the console already shows.
var currentBuildHashes = map[string]string{
	"com.meridianpay.wallet":   hashID("com.meridianpay.wallet/4.2.0"),
	"com.meridianpay.merchant": hashID("com.meridianpay.merchant/2.8.0"),
}

// repackedBuildHashes mirrors the repacked build hash seedApp derives for each
// app, so the events-only reseed attributes the fraud campaign to the same
// malicious build the kill switch targets.
var repackedBuildHashes = map[string]string{
	"com.meridianpay.wallet":   hashID("com.meridianpay.wallet/4.2.0-repack"),
	"com.meridianpay.merchant": hashID("com.meridianpay.merchant/2.8.0-repack"),
}

// runEventsOnly re-ingests just the telemetry stream for the already-seeded
// "meridian" tenant. The control-plane state (apps, policies, audit, …) lives in
// Postgres and survives restarts, but the analytics store is in-memory and is
// cleared whenever the server restarts; this repopulates it without touching the
// durable state (which a full re-seed cannot do, as the tenant slug is unique).
func (s *seeder) runEventsOnly() error {
	ctx := s.ctx

	tenants, _, err := s.store.ListTenants(ctx, registry.Page{Size: 200})
	if err != nil {
		return fmt.Errorf("list tenants: %w", err)
	}
	var tenant *ksealv1.Tenant
	for _, t := range tenants {
		if t.Slug == "meridian" {
			tenant = t
			break
		}
	}
	if tenant == nil {
		return fmt.Errorf("tenant %q not found — run a full seed first", "meridian")
	}

	apps, _, err := s.store.ListApps(ctx, tenant.Id, registry.Page{Size: 200})
	if err != nil {
		return fmt.Errorf("list apps: %w", err)
	}

	ingested := 0
	for _, app := range apps {
		hash, ok := currentBuildHashes[app.PackageId]
		if !ok {
			continue
		}
		if err := s.ingestEvents(tenant.Id, appSeed{
			app:           app,
			currentBuild:  hash,
			repackedBuild: repackedBuildHashes[app.PackageId],
		}); err != nil {
			return err
		}
		ingested++
	}
	log.Printf("events-only reseed complete: %d app(s) for tenant %s (%s)", ingested, tenant.Id, tenant.Slug)
	return nil
}

type appSpec struct {
	name      string
	platform  ksealv1.Platform
	packageID string
	signers   []string
	profile   string
	builds    []buildSpec
	repacked  string
}

type buildSpec struct {
	version  string
	code     int64
	strength string
}

func (s *seeder) seedApp(tenantID string, spec appSpec) (appSeed, error) {
	ctx := s.ctx
	app, err := s.store.CreateApp(ctx, registry.CreateAppInput{
		TenantID:          tenantID,
		Name:              spec.name,
		Platform:          spec.platform,
		PackageID:         spec.packageID,
		SigningIdentities: spec.signers,
	})
	if err != nil {
		return appSeed{}, fmt.Errorf("create app %s: %w", spec.name, err)
	}

	profile, err := s.store.CreateProtectionProfile(ctx, registry.CreateProtectionProfileInput{
		TenantID:       tenantID,
		Name:           spec.profile,
		ModulesEnabled: policyModules,
		DefaultMode:    ksealv1.EnforcementMode_ENFORCEMENT_MODE_STEP_UP,
	})
	if err != nil {
		return appSeed{}, fmt.Errorf("create protection profile %s: %w", spec.profile, err)
	}

	out := appSeed{app: app}
	for _, b := range spec.builds {
		hash := hashID(spec.packageID + "/" + b.version)
		build, err := s.store.CreateBuild(ctx, registry.CreateBuildInput{
			TenantID:            tenantID,
			AppID:               app.Id,
			BuildHash:           hash,
			VersionName:         b.version,
			VersionCode:         b.code,
			ProtectionProfileID: profile.Id,
			Manifest:            buildManifest(b.version, b.strength),
		})
		if err != nil {
			return appSeed{}, fmt.Errorf("create build %s/%s: %w", spec.name, b.version, err)
		}
		out.builds = append(out.builds, build)
		if out.currentBuild == "" {
			out.currentBuild = hash
		}
	}
	out.repackedBuild = hashID(spec.packageID + "/" + spec.repacked)
	log.Printf("app: %s (%s) with %d builds", app.Name, app.Id, len(out.builds))
	return out, nil
}

type thresholds struct{ critical, high, medium, low int }

func (s *seeder) seedPolicy(tenantID, appID, name string, t thresholds, activate bool) (*ksealv1.Policy, error) {
	ctx := s.ctx
	rules := map[string]any{
		"step_up_on": []string{"TRUST_LEVEL_MEDIUM_RISK", "TRUST_LEVEL_HIGH_RISK"},
		"deny_on":    []string{"TRUST_LEVEL_CRITICAL"},
	}
	thr := map[string]int{
		"critical": t.critical, "high_risk": t.high,
		"medium_risk": t.medium, "low_risk": t.low,
	}
	pol, err := s.store.CreatePolicy(ctx, registry.CreatePolicyInput{
		TenantID:        tenantID,
		AppID:           appID,
		Name:            name,
		EnforcementMode: ksealv1.EnforcementMode_ENFORCEMENT_MODE_STEP_UP,
		Rules:           mustJSON(rules),
		RiskThresholds:  mustJSON(thr),
		ModulesEnabled:  policyModules,
	})
	if err != nil {
		return nil, fmt.Errorf("create policy %s: %w", name, err)
	}
	if activate {
		if pol, err = s.store.ActivatePolicy(ctx, tenantID, pol.Id); err != nil {
			return nil, fmt.Errorf("activate policy %s: %w", name, err)
		}
	}
	log.Printf("policy: %s (active=%v)", name, activate)
	return pol, nil
}

func (s *seeder) seedWebhooks(tenantID string) error {
	ctx := s.ctx
	hooks := []struct {
		url    string
		events []ksealv1.EventType
	}{
		{
			url: "https://soc.meridianpay.com/hooks/kseal",
			events: []ksealv1.EventType{
				ksealv1.EventType_EVENT_TYPE_ATTESTATION_FAIL,
				ksealv1.EventType_EVENT_TYPE_APP_INTEGRITY_FAIL,
				ksealv1.EventType_EVENT_TYPE_POLICY_DECISION,
			},
		},
		{
			url: "https://fraud-eng.meridianpay.com/ingest/kseal",
			events: []ksealv1.EventType{
				ksealv1.EventType_EVENT_TYPE_ROOT_RISK,
				ksealv1.EventType_EVENT_TYPE_HOOKING_DETECTED,
				ksealv1.EventType_EVENT_TYPE_OVERLAY_ABUSE,
				ksealv1.EventType_EVENT_TYPE_ACCESSIBILITY_ABUSE,
				ksealv1.EventType_EVENT_TYPE_REMOTE_ACCESS,
			},
		},
	}
	for _, h := range hooks {
		if _, err := s.store.CreateWebhook(ctx, tenantID, h.url, h.events); err != nil {
			return fmt.Errorf("create webhook %s: %w", h.url, err)
		}
	}
	log.Printf("webhooks: %d", len(hooks))
	return nil
}

func (s *seeder) seedSIEM(tenantID string) error {
	_, err := s.siem.CreateConnector(s.ctx, siem.CreateConnectorInput{
		TenantID:         tenantID,
		Kind:             ksealv1.SiemKind_SIEM_KIND_SPLUNK_HEC,
		Endpoint:         "https://http-inputs-meridianpay.splunkcloud.com:8088/services/collector",
		Secret:           randSecret(24),
		Format:           ksealv1.SiemPayloadFormat_SIEM_PAYLOAD_FORMAT_SPLUNK_HEC,
		FieldAllowList:   []string{"event_type", "risk_level", "risk_signals", "build_hash", "policy_hash", "country_or_region"},
		SplunkIndex:      "mobile_risk",
		SplunkSourcetype: "kseal:telemetry",
	})
	if err != nil {
		return fmt.Errorf("create siem connector: %w", err)
	}
	log.Printf("siem: Splunk HEC connector")
	return nil
}

func (s *seeder) seedDataProcessing(tenantID, payID, merchantID string) error {
	ctx := s.ctx
	records := []compliance.DataProcessingInput{
		{
			TenantID:       tenantID,
			DataCategories: []string{"device_integrity_signals", "coarse_geo", "risk_scores"},
			Purpose:        "Payment fraud and account-takeover prevention",
			RetentionDays:  30,
			LegalBasis:     "Legitimate interest (fraud prevention)",
		},
		{
			TenantID:       tenantID,
			AppID:          payID,
			DataCategories: []string{"device_integrity_signals", "coarse_geo", "risk_scores", "app_build_hash"},
			Purpose:        "Wallet transaction risk scoring and step-up authentication",
			RetentionDays:  30,
			LegalBasis:     "Legitimate interest (fraud prevention)",
		},
		{
			TenantID:       tenantID,
			AppID:          merchantID,
			DataCategories: []string{"device_integrity_signals", "risk_scores"},
			Purpose:        "Merchant app integrity monitoring",
			RetentionDays:  14,
			LegalBasis:     "Legitimate interest (fraud prevention)",
		},
	}
	for _, r := range records {
		if _, err := s.comp.PutDataProcessing(ctx, r); err != nil {
			return fmt.Errorf("put data processing: %w", err)
		}
	}
	log.Printf("data-processing: %d records", len(records))
	return nil
}

func (s *seeder) seedAudit(tenantID string, pay, merchant appSeed) error {
	ctx := s.ctx
	entries := []compliance.Entry{
		{Action: "tenant.create", ResourceType: "tenant", ResourceID: tenantID, ActorKeyID: "platform", Metadata: map[string]string{"slug": "meridian", "tier": "enterprise"}},
		{Action: "app.create", ResourceType: "app", ResourceID: pay.app.Id, ActorKeyID: "release-eng", Metadata: map[string]string{"name": "pay-android", "platform": "android"}},
		{Action: "app.create", ResourceType: "app", ResourceID: merchant.app.Id, ActorKeyID: "release-eng", Metadata: map[string]string{"name": "merchant", "platform": "android"}},
		{Action: "build.register", ResourceType: "build", ResourceID: pay.currentBuild, ActorKeyID: "ci-bot", Metadata: map[string]string{"app": "pay-android", "version": "4.2.0"}},
		{Action: "policy.activate", ResourceType: "policy", ResourceID: "payments-baseline", ActorKeyID: "mobile-security-lead", Metadata: map[string]string{"app": "pay-android", "enforcement": "STEP_UP"}},
		{Action: "webhook.create", ResourceType: "webhook", ResourceID: "soc.meridianpay.com", ActorKeyID: "soc-admin", Metadata: map[string]string{"events": "attestation_fail,app_integrity_fail,policy_decision"}},
		{Action: "siem.connector.create", ResourceType: "siem_connector", ResourceID: "splunk-hec", ActorKeyID: "soc-admin", Metadata: map[string]string{"kind": "splunk_hec", "index": "mobile_risk"}},
		{Action: "data_processing.update", ResourceType: "data_processing", ResourceID: pay.app.Id, ActorKeyID: "compliance-owner", Metadata: map[string]string{"retention_days": "30"}},
		// Note: the canary action is recorded by SetCanary (step 11) as a
		// canary.set entry, so it is not duplicated here.
	}
	for _, e := range entries {
		if _, err := s.comp.AppendAudit(ctx, tenantID, e); err != nil {
			return fmt.Errorf("append audit %s: %w", e.Action, err)
		}
	}
	log.Printf("audit: %d entries", len(entries))
	return nil
}

func (s *seeder) seedKillSwitches(tenantID string, pay, merchant appSeed) error {
	ctx := s.ctx
	// Armed: a repackaged pay-android build observed in the wild is disabled.
	if _, err := s.comp.IssueKillSwitch(ctx, compliance.KillSwitchInput{
		TenantID:   tenantID,
		AppID:      pay.app.Id,
		BuildHash:  pay.repackedBuild,
		Command:    ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_DISABLE,
		Reason:     "Repackaged build observed in the wild (app_tamper + attestation_fail, CRITICAL)",
		ActorKeyID: "mobile-security-lead",
	}); err != nil {
		return fmt.Errorf("issue kill switch (disable): %w", err)
	}
	// Re-enabled: an earlier merchant incident has been cleared.
	if _, err := s.comp.IssueKillSwitch(ctx, compliance.KillSwitchInput{
		TenantID:   tenantID,
		AppID:      merchant.app.Id,
		BuildHash:  merchant.repackedBuild,
		Command:    ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_ENABLE,
		Reason:     "Cleared: false positive on internal QA fleet, build re-enabled",
		ActorKeyID: "on-call-eng",
	}); err != nil {
		return fmt.Errorf("issue kill switch (enable): %w", err)
	}
	log.Printf("kill-switches: 1 armed (pay-android), 1 re-enabled (merchant)")
	return nil
}

// trust-session distribution across fused trust levels.
var trustDist = []struct {
	level ksealv1.TrustLevel
	n     int
}{
	{ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED, 72},
	{ksealv1.TrustLevel_TRUST_LEVEL_LOW_RISK, 24},
	{ksealv1.TrustLevel_TRUST_LEVEL_MEDIUM_RISK, 11},
	{ksealv1.TrustLevel_TRUST_LEVEL_HIGH_RISK, 6},
	{ksealv1.TrustLevel_TRUST_LEVEL_CRITICAL, 3},
}

func (s *seeder) seedTrustSessions(tenantID string, pay, merchant appSeed) error {
	ctx := s.ctx
	apps := []appSeed{pay, merchant}
	now := time.Now().Unix()
	var issued, failed int
	for _, d := range trustDist {
		for i := 0; i < d.n; i++ {
			a := apps[s.rng.Intn(len(apps))]
			issuedAt := now - int64(s.rng.Intn(23*3600))
			sess := &registry.TrustSession{
				TokenID:         uuid.NewString(),
				TenantID:        tenantID,
				AppID:           a.app.Id,
				BuildHash:       a.currentBuild,
				InstanceID:      "inst_" + uuid.NewString()[:12],
				PolicyHash:      policyHash,
				RiskLevel:       int32(d.level),
				CapabilityScope: []string{"payments:authorize", "session:refresh"},
				SessionSecret:   randSecret(32),
				IssuedAt:        issuedAt,
				ExpiresAt:       issuedAt + 3600,
			}
			if err := s.store.CreateTrustSession(ctx, sess); err != nil {
				return fmt.Errorf("create trust session: %w", err)
			}
			issued++
		}
	}
	// A handful of failed attestations (status 'failed') for the dashboard.
	for i := 0; i < 9; i++ {
		a := apps[s.rng.Intn(len(apps))]
		issuedAt := now - int64(s.rng.Intn(23*3600))
		if err := s.store.RecordFailedAttestation(ctx, &registry.TrustSession{
			TokenID:    uuid.NewString(),
			TenantID:   tenantID,
			AppID:      a.app.Id,
			BuildHash:  a.repackedBuild,
			InstanceID: "inst_" + uuid.NewString()[:12],
			RiskLevel:  int32(ksealv1.TrustLevel_TRUST_LEVEL_CRITICAL),
			IssuedAt:   issuedAt,
			ExpiresAt:  issuedAt,
		}); err != nil {
			return fmt.Errorf("record failed attestation: %w", err)
		}
		failed++
	}
	log.Printf("trust-sessions: %d issued, %d failed", issued, failed)
	return nil
}

func (s *seeder) printSummary(tenant *ksealv1.Tenant, apiKey string, pay, merchant appSeed) {
	fmt.Println()
	fmt.Println("=========================================================")
	fmt.Println("  Meridian Pay showcase data seeded")
	fmt.Println("=========================================================")
	fmt.Printf("  Tenant ID    : %s\n", tenant.Id)
	fmt.Printf("  Tenant slug  : %s\n", tenant.Slug)
	fmt.Printf("  API key      : %s\n", apiKey)
	fmt.Printf("  API base URL : http://localhost:8080\n")
	fmt.Printf("  pay-android  : %s\n", pay.app.Id)
	fmt.Printf("  merchant     : %s\n", merchant.app.Id)
	fmt.Println("---------------------------------------------------------")
	fmt.Println("  Console login: http://localhost:5173/login")
	fmt.Printf("    Tenant ID    -> %s\n", tenant.Id)
	fmt.Printf("    API key      -> %s\n", apiKey)
	fmt.Printf("    API base URL -> http://localhost:8080\n")
	fmt.Println("=========================================================")
}
