package fleet

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// ConfigFromEnv returns DefaultConfig with any of the following optional
// environment overrides applied. Unset or unparseable values keep the default,
// so the zero-config (NoOps) path needs no environment at all.
//
//	KSEAL_FLEET_WINDOW         e.g. "5m" (Go duration)
//	KSEAL_FLEET_BUCKETS        integer > 0
//	KSEAL_FLEET_SURGE_FACTOR   float > 1
//	KSEAL_FLEET_ABSOLUTE_FLOOR float in (0,1]
//	KSEAL_FLEET_COLDSTART_FLOOR float in (0,1]
//	KSEAL_FLEET_MIN_SAMPLES    integer > 0
//	KSEAL_FLEET_BASELINE_ALPHA float in (0,1]
//	KSEAL_FLEET_VELOCITY_FACTOR float > 1
//	KSEAL_FLEET_VELOCITY_MIN_VOLUME integer > 0
//	KSEAL_FLEET_VELOCITY_COLD_VOLUME integer > 0
//	KSEAL_FLEET_MAX_SCOPES     integer > 0
//	KSEAL_FLEET_SNAPSHOT_TTL   Go duration ("0" or negative disables read caching)
//	KSEAL_FLEET_TRUST_EDGE_REGION bool (see TrustEdgeRegionFromEnv)
func ConfigFromEnv() Config {
	c := DefaultConfig()
	if v := os.Getenv("KSEAL_FLEET_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			c.Window = d
		}
	}
	if v := os.Getenv("KSEAL_FLEET_BUCKETS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.Buckets = n
		}
	}
	if v := os.Getenv("KSEAL_FLEET_SURGE_FACTOR"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 1 {
			c.SurgeFactor = f
		}
	}
	if v := os.Getenv("KSEAL_FLEET_ABSOLUTE_FLOOR"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			c.AbsoluteFloor = f
		}
	}
	if v := os.Getenv("KSEAL_FLEET_COLDSTART_FLOOR"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			c.ColdStartFloor = f
		}
	}
	if v := os.Getenv("KSEAL_FLEET_MIN_SAMPLES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.MinSamples = n
		}
	}
	if v := os.Getenv("KSEAL_FLEET_BASELINE_ALPHA"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f <= 1 {
			c.BaselineAlpha = f
		}
	}
	if v := os.Getenv("KSEAL_FLEET_VELOCITY_FACTOR"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 1 {
			c.VelocityFactor = f
		}
	}
	if v := os.Getenv("KSEAL_FLEET_VELOCITY_MIN_VOLUME"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.VelocityMinVolume = n
		}
	}
	if v := os.Getenv("KSEAL_FLEET_VELOCITY_COLD_VOLUME"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.VelocityColdVolume = n
		}
	}
	if v := os.Getenv("KSEAL_FLEET_MAX_SCOPES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.MaxScopes = n
		}
	}
	if v := os.Getenv("KSEAL_FLEET_SNAPSHOT_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			// A non-positive duration disables caching; New treats <0 as the
			// "disabled" sentinel, so map 0 to -1 to avoid the zero-means-default
			// rule.
			if d <= 0 {
				d = -1
			}
			c.SnapshotTTL = d
		}
	}
	return c
}

// TrustEdgeRegionFromEnv reports whether CDN-injected country headers should be
// trusted as the fleet cohort's region dimension, controlled by
// KSEAL_FLEET_TRUST_EDGE_REGION. It defaults to false: those headers are
// client-spoofable unless the server sits behind a CDN/edge that sets and
// strips them, so operators must opt in explicitly. Only "1", "true", "t",
// "yes", "y", "on" (case-insensitive) enable it.
func TrustEdgeRegionFromEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("KSEAL_FLEET_TRUST_EDGE_REGION"))) {
	case "1", "true", "t", "yes", "y", "on":
		return true
	default:
		return false
	}
}
