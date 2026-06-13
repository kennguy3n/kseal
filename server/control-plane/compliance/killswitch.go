package compliance

import (
	"crypto/ed25519"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// killSwitchDomain is the domain-separation tag for the signed kill-switch
// preimage, distinct from the config-envelope and request-proof domains so a
// kill-switch signature can never be confused with another signed structure.
const killSwitchDomain = "kseal/v1/kill-switch"

// killSwitchPreimage builds the canonical, domain-separated, length-prefixed
// bytes a kill-switch command is signed over. The scope (tenant/app/build), the
// command, the monotonic version (anti-rollback), the issue time, and the
// reason are all authenticated, so a forged or altered command fails
// verification and is treated as a no-op (fail-safe).
func killSwitchPreimage(ks *ksealv1.SignedKillSwitch) []byte {
	buf := make([]byte, 0, 64+len(ks.TenantId)+len(ks.AppId)+len(ks.BuildHash)+len(ks.Reason))
	buf = appendLP(buf, []byte(killSwitchDomain))
	buf = appendLP(buf, []byte(ks.TenantId))
	buf = appendLP(buf, []byte(ks.AppId))
	buf = appendLP(buf, []byte(ks.BuildHash))
	buf = appendUint64(buf, uint64(ks.Command))
	buf = appendUint64(buf, uint64(ks.Version))
	buf = appendUint64(buf, uint64(ks.IssuedAt))
	buf = appendLP(buf, []byte(ks.Reason))
	return buf
}

// signKillSwitch sets ks.Signature to the Ed25519 signature over its canonical
// preimage using priv. The signature covers every field except itself.
func signKillSwitch(priv ed25519.PrivateKey, ks *ksealv1.SignedKillSwitch) {
	ks.Signature = ed25519.Sign(priv, killSwitchPreimage(ks))
}

// VerifyKillSwitch reports whether ks carries a valid Ed25519 signature by pub
// over its canonical preimage. It returns false (never panics) for a malformed
// key or signature length. This is the fail-safe gate: state only flips when
// this returns true.
func VerifyKillSwitch(pub ed25519.PublicKey, ks *ksealv1.SignedKillSwitch) bool {
	if ks == nil || len(pub) != ed25519.PublicKeySize || len(ks.Signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, killSwitchPreimage(ks), ks.Signature)
}

// killSwitchScope identifies a kill switch within a tenant. The empty string is
// a wildcard: empty app_id is tenant-wide, empty build_hash covers all builds.
type killSwitchScope struct {
	appID     string
	buildHash string
}

// matches reports whether a configured scope applies to a concrete query scope.
func (s killSwitchScope) matches(q killSwitchScope) bool {
	if s.appID != "" && s.appID != q.appID {
		return false
	}
	if s.buildHash != "" && s.buildHash != q.buildHash {
		return false
	}
	return true
}

// specificity ranks how targeted a scope is; the most specific matching switch
// wins so an app- or build-level ENABLE can override a tenant-wide DISABLE.
func (s killSwitchScope) specificity() int {
	n := 0
	if s.appID != "" {
		n += 2
	}
	if s.buildHash != "" {
		n++
	}
	return n
}

// resolveEffective returns the most specific kill switch applicable to the
// query scope, or nil when none applies. With no applicable switch, callers
// treat the command as ENABLE (default, fail-open for availability — a disable
// requires an explicit, valid, signed command).
func resolveEffective(switches []*ksealv1.SignedKillSwitch, q killSwitchScope) *ksealv1.SignedKillSwitch {
	var best *ksealv1.SignedKillSwitch
	bestRank := -1
	for _, ks := range switches {
		sc := killSwitchScope{appID: ks.AppId, buildHash: ks.BuildHash}
		if !sc.matches(q) {
			continue
		}
		if r := sc.specificity(); r > bestRank {
			best = ks
			bestRank = r
		}
	}
	return best
}
