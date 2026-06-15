// Command kseal-server is the unified kseal control-plane + data-plane server.
// It loads config, connects to Postgres and Redis, runs migrations, builds every
// service, and serves the six Connect APIs plus health and metrics endpoints
// over h2c.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"

	cfgpkg "github.com/kennguy3n/kseal/server/shared/config"
	"github.com/kennguy3n/kseal/server/shared/crypto"
	"github.com/kennguy3n/kseal/server/shared/db"
	"github.com/kennguy3n/kseal/server/shared/middleware"
	"github.com/kennguy3n/kseal/server/shared/risk"
	"github.com/kennguy3n/kseal/server/shared/telemetry"

	"github.com/kennguy3n/kseal/server/control-plane/compliance"
	"github.com/kennguy3n/kseal/server/control-plane/migrations"
	"github.com/kennguy3n/kseal/server/control-plane/registry"

	"github.com/kennguy3n/kseal/server/data-plane/attestation"
	"github.com/kennguy3n/kseal/server/data-plane/canary"
	cfgsvc "github.com/kennguy3n/kseal/server/data-plane/config"
	"github.com/kennguy3n/kseal/server/data-plane/fleet"
	"github.com/kennguy3n/kseal/server/data-plane/guardrails"
	"github.com/kennguy3n/kseal/server/data-plane/ingest"
	"github.com/kennguy3n/kseal/server/data-plane/query"
	"github.com/kennguy3n/kseal/server/data-plane/siem"
	"github.com/kennguy3n/kseal/server/data-plane/trust"
	"github.com/kennguy3n/kseal/server/data-plane/webhook"
)

func main() {
	if err := run(); err != nil {
		// Logger may not be up yet; stderr is the reliable sink.
		os.Stderr.WriteString("fatal: " + err.Error() + "\n")
		os.Exit(1)
	}
}

func run() error {
	cfg, err := cfgpkg.Load()
	if err != nil {
		return err
	}
	logger := middleware.NewLogger(cfg.LogLevel, cfg.Env)
	logger.Info().Str("env", cfg.Env).Str("addr", cfg.HTTPAddr).Msg("starting kseal-server")

	tel, err := telemetry.Setup("kseal-server", cfg.Env, telemetry.Options{
		OTLPEndpoint:    cfg.OTLPEndpoint,
		OTLPSampleRatio: cfg.OTLPSampleRatio,
		OTLPInsecure:    cfg.OTLPInsecure,
	})
	if err != nil {
		return err
	}
	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tel.Shutdown(shutdownCtx)
	}()

	// Postgres + migrations.
	database, err := db.New(rootCtx, cfg.PostgresDSN)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Migrate(rootCtx, migrations.FS); err != nil {
		return err
	}
	logger.Info().Msg("migrations applied")

	// Redis (TLS + AUTH optional, default plaintext).
	rdb, err := middleware.NewRedis(rootCtx, middleware.RedisConfig{
		Addr:     cfg.RedisAddr,
		DB:       cfg.RedisDB,
		Password: cfg.RedisPassword,
		TLS:      cfg.RedisTLS,
		CAFile:   cfg.RedisCAFile,
	})
	if err != nil {
		return err
	}
	defer func() { _ = rdb.Close() }()

	enc, err := crypto.NewEncryptor(cfg.KEK)
	if err != nil {
		return err
	}
	// Tenant sealer: platform KEK by default, or per-tenant customer-managed
	// keys (BYOK/CMK) when KSEAL_CMK_KMS_URI is configured.
	sealer, err := buildTenantSealer(cfg, enc, database)
	if err != nil {
		return err
	}
	store := registry.NewPostgresStore(database, sealer)

	// Build services.
	registrySvc := registry.NewService(store)
	webhookSvc := webhook.NewService(store)

	nonceStore := trust.NewNonceStore(rdb, cfg.NonceTTL)
	verifier := attestation.NewProductionVerifier()
	trustSvc := trust.NewService(store, nonceStore, verifier, cfg.TrustTokenTTL, cfg.FeatureFlags)

	configSvc := cfgsvc.NewService(store, cfgsvc.NewSigner(store), cfg.ConfigTTL)

	// Enterprise trust & compliance: hash-chained audit trail + data-processing
	// registry, signed kill switch, and canary rollout with auto-rollback. All
	// flag-gated per tenant (default off); reads/writes are tenant-isolated.
	complianceStore := compliance.NewPostgresStore(database, store)
	complianceSvc := compliance.NewService(complianceStore, store)
	canaryReg := canary.NewRegistry()
	detector := guardrails.NewDetector(0)
	canaryCtl := canary.NewController(complianceStore, canary.GuardrailHealth{Detector: detector}, canaryReg, canary.Config{})
	// Wire optional, flag-gated compliance behavior into the hot paths: candidate
	// selection + kill-switch delivery in config, and the canary health feed in
	// trust. Disabled per tenant unless the matching feature flag is on.
	configSvc.AttachCompliance(canaryReg, complianceStore, cfg.FeatureFlags)
	trustSvc.AttachCanaryHealth(detector, canaryReg)

	// Population-level fleet-anomaly detection: learns each app's baseline
	// prevalence of coordinated-abuse signals and fuses a server-derived
	// FLEET_ANOMALY risk bit during a surge. In-process, O(1)/attestation,
	// bounded memory. Flag-gated per tenant (compliance.FlagFleetAnomaly,
	// default off), so the per-instance decision is unchanged on main.
	fleetEngine := fleet.New(fleet.ConfigFromEnv())
	trustSvc.AttachFleetGuard(fleetEngine, fleet.TrustEdgeRegionFromEnv())

	dispatcher := webhook.NewDispatcher(store, webhook.DispatcherConfig{}, tel.Metrics)
	defer dispatcher.Stop()

	// SIEM export: per-tenant connector store (RLS-isolated, secrets sealed) and
	// the async, backpressured exporter fed from the same ingest write path.
	siemMetrics, err := siem.NewMetrics()
	if err != nil {
		return err
	}
	siemStore := siem.NewPostgresConnectorStore(database, enc)
	if err := siemStore.EnsureSchema(rootCtx); err != nil {
		return err
	}
	siemExporter := siem.NewExporter(siemStore, siem.ExporterConfig{}, siemMetrics)
	defer siemExporter.Stop()
	siemSvc := siem.NewService(siemStore)

	validator := ingest.NewCachedAppValidator(store, 30*time.Second)
	quota := ingest.NewQuota(rdb, cfg.IngestQuotaPerMinute)
	// Data-plane backends: default in-memory (unchanged), or the production
	// Kafka broker + ClickHouse store when explicitly selected. A selected
	// backend that cannot be reached fails closed here (server refuses to start).
	broker, err := buildBroker(rootCtx, cfg, logger)
	if err != nil {
		return err
	}
	analytics, rawStore, analyticsCleanup, err := buildAnalytics(rootCtx, cfg)
	if err != nil {
		broker.Close()
		return err
	}
	logger.Info().Str("broker", cfg.DataPlane.Broker).Str("analytics", cfg.DataPlane.Analytics).Msg("data-plane backends ready")

	writer := ingest.NewWriter(broker, analytics, 0, 0)
	writer.SetWriteErrorHandler(func(werr error) {
		logger.Error().Err(werr).Msg("analytics store flush failed")
	})
	// Fan validated telemetry out to webhook subscribers AND the SIEM exporter.
	writer.SetEventSink(fanoutSink{[]ingest.EventSink{
		webhookSink{dispatcher},
		siemSink{siemExporter},
	}})
	// The writer's lifecycle is bound to the broker, not rootCtx: it runs until
	// the broker closes its hand-off channel. On shutdown we close the broker
	// (which stops the consumer and closes the channel), so the writer drains
	// every buffered event to the store before exiting — no telemetry is lost.
	writerDone := make(chan struct{})
	go func() {
		writer.Run(context.Background())
		close(writerDone)
	}()
	// Cleanup order matters: drain the pipeline before closing the store.
	// Deferred functions run LIFO, so analyticsCleanup is registered first
	// (runs last) and the broker-close/writer-drain is registered second (runs
	// first): broker.Close stops the consumer and closes the hand-off channel,
	// the writer drains the remaining backlog to the store, then the store closes.
	defer analyticsCleanup()
	defer func() {
		broker.Close()
		<-writerDone
	}()

	ingestSvc, err := ingest.NewService(validator, quota, broker)
	if err != nil {
		return err
	}

	querySvc := query.NewService(store, analytics)
	querySvc.AttachFleetGuard(fleetEngine, cfg.FeatureFlags)

	// Raw-telemetry retention: purge per-tenant raw events past their window
	// (platform default KSEAL_RAW_RETENTION_DAYS), retaining aggregates. Tracked
	// in bg so it drains before the DB pool closes on shutdown.
	var bg sync.WaitGroup
	purger := ingest.NewPurger(rawStore, registry.NewRetentionResolver(database), cfg.RawRetentionDays)
	bg.Add(1)
	go func() {
		defer bg.Done()
		purger.Run(rootCtx, time.Hour, func(err error) {
			logger.Error().Err(err).Msg("raw-event retention purge failed")
		})
	}()

	// Canary auto-rollback controller: refreshes the in-memory active-canary
	// snapshot the config/trust hot paths read, and reverts any candidate cohort
	// that breaches its guardrail block-rate threshold. Harmless with no active
	// canaries; tracked in bg so it drains before the DB pool closes.
	bg.Add(1)
	go func() {
		defer bg.Done()
		canaryCtl.Run(rootCtx)
	}()

	// Fleet-anomaly metrics sampler: periodically reflects the engine's active
	// anomalies into the kseal_fleet_anomaly_active gauge. Cheap (reads bounded
	// in-memory state); tracked in bg so it stops cleanly on shutdown.
	bg.Add(1)
	go func() {
		defer bg.Done()
		runFleetMetricsSampler(rootCtx, fleetEngine, tel.Metrics, 15*time.Second)
	}()

	// Interceptors.
	limiter := middleware.NewRedisRateLimiter(rdb, cfg.RateLimitPerSecond, cfg.RateLimitBurst, "rl")
	ic := &middleware.Interceptors{
		Logger:      logger,
		Metrics:     tel.Metrics,
		Tracer:      *tel,
		Limiter:     limiter,
		Validator:   store,
		RequireAuth: controlPlaneProcedures(),
	}
	opts := ic.Chain()

	mux := http.NewServeMux()
	mux.Handle(ksealv1connect.NewRegistryServiceHandler(registrySvc, opts))
	mux.Handle(ksealv1connect.NewTrustServiceHandler(trustSvc, opts))
	mux.Handle(ksealv1connect.NewConfigServiceHandler(configSvc, opts))
	mux.Handle(ksealv1connect.NewIngestServiceHandler(ingestSvc, opts))
	mux.Handle(ksealv1connect.NewWebhookServiceHandler(webhookSvc, opts))
	mux.Handle(ksealv1connect.NewQueryServiceHandler(querySvc, opts))
	mux.Handle(ksealv1connect.NewSiemServiceHandler(siemSvc, opts))
	mux.Handle(ksealv1connect.NewComplianceServiceHandler(complianceSvc, opts))

	// Single /metrics exposition combining the platform and SIEM registries.
	mux.Handle("/metrics", siem.CombinedMetricsHandler(tel.Metrics.Handler(), siemMetrics.Handler()))
	mux.Handle("/healthz", telemetry.HealthHandler())
	mux.Handle("/readyz", telemetry.HealthHandler(
		telemetry.Check{Name: "postgres", Func: database.Ping},
		telemetry.Check{Name: "redis", Func: func(ctx context.Context) error { return rdb.Ping(ctx).Err() }},
	))

	handler := middleware.RequestID(middleware.CORS(cfg.CORSAllowedOrigins, mux))
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           h2c.NewHandler(handler, &http2.Server{}),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info().Str("addr", cfg.HTTPAddr).Msg("listening")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-rootCtx.Done():
		logger.Info().Msg("shutdown signal received")
	case err := <-errCh:
		stop()
		bg.Wait()
		return err
	}

	// Cancel background workers and let them drain before the deferred Postgres /
	// Redis closes run, so an in-flight retention purge cannot race the pool
	// shutdown and emit a spurious error.
	stop()
	bg.Wait()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// runFleetMetricsSampler periodically reflects the fleet engine's currently
// anomalous (tenant, app, build, region) cohorts into the FleetAnomaly gauge,
// clearing cohorts that have recovered. It returns when ctx is cancelled.
//
// It updates the gauge by diffing against the previous tick's active set rather
// than calling Reset(): active series are re-set to 1 (idempotent) and only the
// cohorts that have recovered are deleted. Reset() would briefly drop every
// series to absent, so a scrape landing mid-tick could see zero anomalies and
// flap a "no longer under attack" alert; the diff keeps each active series
// continuously present.
func runFleetMetricsSampler(ctx context.Context, engine *fleet.Engine, m *telemetry.Metrics, interval time.Duration) {
	if engine == nil || m == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// cohortLabels is the gauge's label tuple in declaration order.
	type cohortLabels = [4]string
	active := map[cohortLabels]struct{}{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			next := make(map[cohortLabels]struct{}, len(active))
			for _, a := range engine.Snapshot() {
				lv := cohortLabels{a.TenantID, a.AppID, a.BuildHash, a.Region}
				m.FleetAnomaly.WithLabelValues(lv[:]...).Set(1)
				next[lv] = struct{}{}
			}
			// Delete only cohorts that were active last tick but recovered now,
			// so still-anomalous cohorts never momentarily read absent/zero.
			for lv := range active {
				if _, ok := next[lv]; !ok {
					m.FleetAnomaly.DeleteLabelValues(lv[:]...)
				}
			}
			active = next
		}
	}
}

// buildTenantSealer selects how tenant secret material is sealed at rest. When
// KSEAL_CMK_KMS_URI is empty (default) every tenant uses the platform KEK and
// behavior is unchanged. When set, customer-managed keys (BYOK/CMK) are enabled:
// tenants with a configured cmk_kms_uri get per-tenant DEKs wrapped by their own
// KMS key, and the rest still fall back to the platform KEK.
func buildTenantSealer(cfg *cfgpkg.Config, platform *crypto.Encryptor, database *db.DB) (crypto.TenantSealer, error) {
	var base crypto.TenantSealer = platform
	if cfg.CMKKMSURI != "" {
		var kmsOpts []crypto.HTTPKMSOption
		if cfg.CMKKMSAuthToken != "" {
			kmsOpts = append(kmsOpts, crypto.WithAuthToken(cfg.CMKKMSAuthToken))
		}
		kms, err := crypto.NewHTTPKMSClient(cfg.CMKKMSURI, kmsOpts...)
		if err != nil {
			return nil, err
		}
		resolver := registry.NewCMKResolver(database, registry.DefaultCMKCacheTTL)
		base, err = crypto.NewCMKKeyManager(platform, kms, resolver)
		if err != nil {
			return nil, err
		}
	}
	// Dedicated/regulated isolation tier wraps the base sealer: tenants flagged
	// dedicated (and without a CMK key) get a per-tenant HKDF-derived key domain;
	// all others delegate to base with unchanged behavior. Off by default.
	if cfg.DedicatedIsolation {
		isolation := registry.NewDedicatedResolver(database, registry.DefaultCMKCacheTTL)
		return crypto.NewDedicatedKeyManager(base, cfg.KEK, isolation)
	}
	return base, nil
}

// webhookSink adapts the ingest write path to the webhook dispatcher, fanning
// each validated telemetry event out to subscribers. It carries only coarse,
// non-PII fields.
type webhookSink struct{ d *webhook.Dispatcher }

func (s webhookSink) Emit(e ingest.StoredEvent) {
	// Project to the server layout so both the raw integer and the named
	// signals are in one namespace regardless of how the row was stored.
	serverBits := risk.NormalizeStored(e.RiskBits, e.RiskBitsLayout)
	signals := risk.SignalNames(serverBits)
	if signals == nil {
		signals = []string{}
	}
	payload, err := json.Marshal(struct {
		TenantID    string   `json:"tenant_id"`
		AppID       string   `json:"app_id"`
		EventType   string   `json:"event_type"`
		RiskBits    uint64   `json:"risk_bits"`
		RiskSignals []string `json:"risk_signals"`
		Confidence  string   `json:"confidence"`
		PolicyHash  string   `json:"policy_hash"`
		Platform    string   `json:"platform"`
		TimeBucket  int64    `json:"time_bucket"`
	}{
		TenantID:    e.TenantID,
		AppID:       e.AppID,
		EventType:   e.EventType.String(),
		RiskBits:    serverBits,
		RiskSignals: signals,
		Confidence:  e.Confidence.String(),
		PolicyHash:  e.PolicyHash,
		Platform:    e.Platform.String(),
		TimeBucket:  e.TimeBucket,
	})
	if err != nil {
		return
	}
	s.d.Submit(webhook.Event{
		TenantID:  e.TenantID,
		AppID:     e.AppID,
		Type:      e.EventType,
		Payload:   string(payload),
		Timestamp: e.ReceivedAt,
	})
}

// fanoutSink delivers each event to several sinks. It is synchronous but every
// downstream sink is itself non-blocking (bounded queue + load-shed), so the
// ingest write path is never stalled by a slow subscriber.
type fanoutSink struct{ sinks []ingest.EventSink }

func (f fanoutSink) Emit(e ingest.StoredEvent) {
	for _, s := range f.sinks {
		s.Emit(e)
	}
}

// siemSink adapts the ingest write path to the SIEM exporter, projecting a
// StoredEvent onto the minimized, non-PII Event the exporter understands.
type siemSink struct{ ex *siem.Exporter }

func (s siemSink) Emit(e ingest.StoredEvent) {
	s.ex.Submit(siem.Event{
		TenantID:  e.TenantID,
		AppID:     e.AppID,
		EventType: e.EventType,
		RiskLevel: e.RiskLevel,
		// Normalize to the server layout so the exporter's raw risk_bits and
		// the derived risk_signals are consistent for any stored layout.
		RiskBits:         risk.NormalizeStored(e.RiskBits, e.RiskBitsLayout),
		Confidence:       e.Confidence,
		BuildHash:        e.BuildHash,
		PolicyHash:       e.PolicyHash,
		InstallKeyHash:   e.InstallKeyHash,
		CoarseTimeBucket: e.TimeBucket,
		Country:          e.Country,
	})
}

// controlPlaneProcedures lists procedures that require a valid API key. Device
// -plane procedures (trust, config, ingest) authenticate via request body and
// signed proofs instead.
func controlPlaneProcedures() map[string]bool {
	return map[string]bool{
		ksealv1connect.RegistryServiceCreateTenantProcedure:                true,
		ksealv1connect.RegistryServiceGetTenantProcedure:                   true,
		ksealv1connect.RegistryServiceListTenantsProcedure:                 true,
		ksealv1connect.RegistryServiceUpdateTenantProcedure:                true,
		ksealv1connect.RegistryServiceCreateAppProcedure:                   true,
		ksealv1connect.RegistryServiceGetAppProcedure:                      true,
		ksealv1connect.RegistryServiceListAppsProcedure:                    true,
		ksealv1connect.RegistryServiceSearchAppsProcedure:                  true,
		ksealv1connect.RegistryServiceCreateBuildProcedure:                 true,
		ksealv1connect.RegistryServiceGetBuildProcedure:                    true,
		ksealv1connect.RegistryServiceListBuildsProcedure:                  true,
		ksealv1connect.RegistryServiceCreatePolicyProcedure:                true,
		ksealv1connect.RegistryServiceGetActivePolicyProcedure:             true,
		ksealv1connect.RegistryServiceListPoliciesProcedure:                true,
		ksealv1connect.RegistryServiceActivatePolicyProcedure:              true,
		ksealv1connect.RegistryServiceCreateProtectionProfileProcedure:     true,
		ksealv1connect.RegistryServiceListProtectionProfilesProcedure:      true,
		ksealv1connect.WebhookServiceRegisterWebhookProcedure:              true,
		ksealv1connect.WebhookServiceListWebhooksProcedure:                 true,
		ksealv1connect.WebhookServiceDeleteWebhookProcedure:                true,
		ksealv1connect.QueryServiceListEventsProcedure:                     true,
		ksealv1connect.QueryServiceGetTenantOverviewProcedure:              true,
		ksealv1connect.QueryServiceGetTrustSessionStatsProcedure:           true,
		ksealv1connect.SiemServiceRegisterConnectorProcedure:               true,
		ksealv1connect.SiemServiceListConnectorsProcedure:                  true,
		ksealv1connect.SiemServiceDeleteConnectorProcedure:                 true,
		ksealv1connect.ComplianceServiceListAuditEventsProcedure:           true,
		ksealv1connect.ComplianceServiceVerifyAuditChainProcedure:          true,
		ksealv1connect.ComplianceServiceGetDataProcessingRegistryProcedure: true,
		ksealv1connect.ComplianceServicePutDataProcessingRecordProcedure:   true,
		ksealv1connect.ComplianceServiceIssueKillSwitchProcedure:           true,
		ksealv1connect.ComplianceServiceGetKillSwitchStateProcedure:        true,
		ksealv1connect.ComplianceServiceListKillSwitchesProcedure:          true,
		ksealv1connect.ComplianceServiceSetCanaryRolloutProcedure:          true,
		ksealv1connect.ComplianceServiceGetCanaryStatusProcedure:           true,
		ksealv1connect.ComplianceServicePromoteCanaryProcedure:             true,
		ksealv1connect.ComplianceServiceRollbackCanaryProcedure:            true,
	}
}
