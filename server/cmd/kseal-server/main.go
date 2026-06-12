// Command kseal-server is the unified kseal control-plane + data-plane server.
// It loads config, connects to Postgres and Redis, runs migrations, builds every
// service, and serves the five Connect APIs plus health and metrics endpoints
// over h2c.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"

	cfgpkg "github.com/kennguy3n/kseal/server/shared/config"
	"github.com/kennguy3n/kseal/server/shared/crypto"
	"github.com/kennguy3n/kseal/server/shared/db"
	"github.com/kennguy3n/kseal/server/shared/middleware"
	"github.com/kennguy3n/kseal/server/shared/telemetry"

	"github.com/kennguy3n/kseal/server/control-plane/migrations"
	"github.com/kennguy3n/kseal/server/control-plane/registry"

	"github.com/kennguy3n/kseal/server/data-plane/attestation"
	cfgsvc "github.com/kennguy3n/kseal/server/data-plane/config"
	"github.com/kennguy3n/kseal/server/data-plane/ingest"
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

	tel, err := telemetry.Setup("kseal-server", cfg.Env)
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

	// Redis.
	rdb, err := middleware.NewRedis(rootCtx, cfg.RedisAddr, cfg.RedisDB)
	if err != nil {
		return err
	}
	defer func() { _ = rdb.Close() }()

	enc, err := crypto.NewEncryptor(cfg.KEK)
	if err != nil {
		return err
	}
	store := registry.NewPostgresStore(database, enc)

	// Build services.
	registrySvc := registry.NewService(store)
	webhookSvc := webhook.NewService(store)

	nonceStore := trust.NewNonceStore(rdb, cfg.NonceTTL)
	verifier := attestation.NewProductionVerifier()
	trustSvc := trust.NewService(store, nonceStore, verifier, cfg.TrustTokenTTL)

	configSvc := cfgsvc.NewService(store, cfgsvc.NewSigner(store), cfg.ConfigTTL)

	dispatcher := webhook.NewDispatcher(store, webhook.DispatcherConfig{}, tel.Metrics)
	defer dispatcher.Stop()

	validator := ingest.NewCachedAppValidator(store, 30*time.Second)
	quota := ingest.NewQuota(rdb, cfg.IngestQuotaPerMinute)
	broker := ingest.NewChannelBroker(0)
	analytics := ingest.NewInMemoryAnalyticsStore()
	writer := ingest.NewWriter(broker, analytics, 0, 0)
	// Fan validated telemetry out to registered webhook subscribers.
	writer.SetEventSink(webhookSink{dispatcher})
	go writer.Run(rootCtx)
	ingestSvc, err := ingest.NewService(validator, quota, broker)
	if err != nil {
		return err
	}

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

	mux.Handle("/metrics", tel.Metrics.Handler())
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
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// webhookSink adapts the ingest write path to the webhook dispatcher, fanning
// each validated telemetry event out to subscribers. It carries only coarse,
// non-PII fields.
type webhookSink struct{ d *webhook.Dispatcher }

func (s webhookSink) Emit(e ingest.StoredEvent) {
	payload, err := json.Marshal(struct {
		TenantID   string `json:"tenant_id"`
		AppID      string `json:"app_id"`
		EventType  string `json:"event_type"`
		RiskBits   uint64 `json:"risk_bits"`
		Confidence string `json:"confidence"`
		PolicyHash string `json:"policy_hash"`
		Platform   string `json:"platform"`
		TimeBucket int64  `json:"time_bucket"`
	}{
		TenantID:   e.TenantID,
		AppID:      e.AppID,
		EventType:  e.EventType.String(),
		RiskBits:   e.RiskBits,
		Confidence: e.Confidence.String(),
		PolicyHash: e.PolicyHash,
		Platform:   e.Platform.String(),
		TimeBucket: e.TimeBucket,
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

// controlPlaneProcedures lists procedures that require a valid API key. Device
// -plane procedures (trust, config, ingest) authenticate via request body and
// signed proofs instead.
func controlPlaneProcedures() map[string]bool {
	return map[string]bool{
		ksealv1connect.RegistryServiceCreateTenantProcedure:            true,
		ksealv1connect.RegistryServiceGetTenantProcedure:               true,
		ksealv1connect.RegistryServiceListTenantsProcedure:             true,
		ksealv1connect.RegistryServiceUpdateTenantProcedure:            true,
		ksealv1connect.RegistryServiceCreateAppProcedure:               true,
		ksealv1connect.RegistryServiceGetAppProcedure:                  true,
		ksealv1connect.RegistryServiceListAppsProcedure:                true,
		ksealv1connect.RegistryServiceCreateBuildProcedure:             true,
		ksealv1connect.RegistryServiceGetBuildProcedure:                true,
		ksealv1connect.RegistryServiceListBuildsProcedure:              true,
		ksealv1connect.RegistryServiceCreatePolicyProcedure:            true,
		ksealv1connect.RegistryServiceGetActivePolicyProcedure:         true,
		ksealv1connect.RegistryServiceListPoliciesProcedure:            true,
		ksealv1connect.RegistryServiceActivatePolicyProcedure:          true,
		ksealv1connect.RegistryServiceCreateProtectionProfileProcedure: true,
		ksealv1connect.RegistryServiceListProtectionProfilesProcedure:  true,
		ksealv1connect.WebhookServiceRegisterWebhookProcedure:          true,
		ksealv1connect.WebhookServiceListWebhooksProcedure:             true,
		ksealv1connect.WebhookServiceDeleteWebhookProcedure:            true,
	}
}
