// Package canary implements staged config rollout: deterministic per-instance
// bucketing for candidate selection and an auto-rollback controller that
// withdraws a rollout when guardrail health degrades. Rollout state lives in the
// control-plane compliance store; this package is the data-plane runtime that
// reads it (selection) and acts on it (rollback).
package canary

import (
	"crypto/sha256"
	"encoding/binary"
)

// InCanary reports whether an instance falls in the candidate cohort for a
// rollout at the given percent. Bucketing is deterministic and tenant-scoped:
// the same instance always lands in the same bucket for a given (tenant, app),
// so an instance does not flip between candidate and stable across config
// fetches. It is fail-safe — an empty instanceID stays on the stable config.
//
//	bucket = SHA256(tenant_id || 0x00 || app_id || 0x00 || instance_id)[:8] % 100
//	candidate = bucket < percent
func InCanary(tenantID, appID, instanceID string, percent uint32) bool {
	if percent == 0 || instanceID == "" {
		return false
	}
	if percent >= 100 {
		return true
	}
	return bucket(tenantID, appID, instanceID) < percent
}

// bucket maps an instance to a stable value in [0,100). Including the tenant and
// app in the hash means the same instance id under different tenants/apps gets
// independent buckets, so cohorts never correlate across tenants (privacy) and
// a rollout in one app does not bias another.
func bucket(tenantID, appID, instanceID string) uint32 {
	h := sha256.New()
	h.Write([]byte(tenantID))
	h.Write([]byte{0})
	h.Write([]byte(appID))
	h.Write([]byte{0})
	h.Write([]byte(instanceID))
	sum := h.Sum(nil)
	return uint32(binary.BigEndian.Uint64(sum[:8]) % 100)
}
