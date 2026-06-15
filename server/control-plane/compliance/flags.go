package compliance

// Feature-flag names for the enterprise trust & compliance capabilities. They
// are resolved per tenant via the shared FeatureFlags (env KSEAL_FEATURE_FLAGS);
// all default off so none change baseline behavior on main.
const (
	// FlagAuditTrail gates writing audit events for control-plane mutations.
	// Reads (ListAuditEvents/VerifyAuditChain) are always served.
	FlagAuditTrail = "audit_trail"
	// FlagKillSwitch gates delivery of signed kill switches in the config
	// envelope. Issuing and reading state are always available; only the
	// data-plane delivery is gated.
	FlagKillSwitch = "kill_switch"
	// FlagCanaryRollout gates candidate-cohort selection in config delivery and
	// the guardrail health feed. The rollout admin RPCs are always available.
	FlagCanaryRollout = "canary_rollout"
	// FlagDedicatedTier gates the dedicated-isolation key domain for a tenant.
	FlagDedicatedTier = "dedicated_tier"
	// FlagFleetAnomaly gates population-level fleet-anomaly detection in the
	// trust path: observing attestations into the fleet engine and fusing the
	// server-derived FLEET_ANOMALY risk bit during a surge. Default off, so the
	// per-instance decision is unchanged on main.
	FlagFleetAnomaly = "fleet_anomaly"
)
