package risk

import (
	"math"
	"testing"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

func TestFuse(t *testing.T) {
	got := Fuse(BitDebugger, BitAttestationFail)
	if got != BitDebugger|BitAttestationFail {
		t.Fatalf("fuse = %b", got)
	}
}

func TestScoreDefaultAndWeights(t *testing.T) {
	base := Score(BitRootJailbreak, nil)
	if base == 0 {
		t.Fatal("expected nonzero default score for root/jailbreak")
	}
	weighted := Score(BitRootJailbreak, map[uint32]uint32{0: 999})
	if weighted != 999 {
		t.Fatalf("weighted score = %d, want 999", weighted)
	}
}

func TestScoreSaturatesOnOverflow(t *testing.T) {
	// Two bits each weighted near uint32 max must clamp at MaxUint32 rather
	// than wrap, matching the Rust core's saturating_add.
	got := Score(BitRootJailbreak|BitEmulator, map[uint32]uint32{
		0: math.MaxUint32 - 1,
		2: 100,
	})
	if got != math.MaxUint32 {
		t.Fatalf("saturating score = %d, want %d", got, uint32(math.MaxUint32))
	}
}

func TestLevelDefaultThresholds(t *testing.T) {
	if l := Level(0, nil); l != ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED {
		t.Fatalf("score 0 -> %v", l)
	}
	if l := Level(200, nil); l != ksealv1.TrustLevel_TRUST_LEVEL_CRITICAL {
		t.Fatalf("score 200 -> %v", l)
	}
	if l := Level(60, nil); l != ksealv1.TrustLevel_TRUST_LEVEL_MEDIUM_RISK {
		t.Fatalf("score 60 -> %v", l)
	}
}

func TestLevelCustomThresholds(t *testing.T) {
	th := map[string]uint32{"HIGH_RISK": 10, "CRITICAL": 100}
	if l := Level(10, th); l != ksealv1.TrustLevel_TRUST_LEVEL_HIGH_RISK {
		t.Fatalf("custom score 10 -> %v", l)
	}
	if l := Level(5, th); l != ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED {
		t.Fatalf("custom score 5 -> %v", l)
	}
}

func TestDecision(t *testing.T) {
	cases := []struct {
		level ksealv1.TrustLevel
		mode  ksealv1.EnforcementMode
		want  ksealv1.RequestProofResult_Decision
	}{
		{ksealv1.TrustLevel_TRUST_LEVEL_CRITICAL, ksealv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE, ksealv1.RequestProofResult_DECISION_ALLOW},
		{ksealv1.TrustLevel_TRUST_LEVEL_CRITICAL, ksealv1.EnforcementMode_ENFORCEMENT_MODE_BLOCK, ksealv1.RequestProofResult_DECISION_DENY},
		{ksealv1.TrustLevel_TRUST_LEVEL_HIGH_RISK, ksealv1.EnforcementMode_ENFORCEMENT_MODE_STEP_UP, ksealv1.RequestProofResult_DECISION_STEP_UP},
		{ksealv1.TrustLevel_TRUST_LEVEL_HIGH_RISK, ksealv1.EnforcementMode_ENFORCEMENT_MODE_BLOCK, ksealv1.RequestProofResult_DECISION_DENY},
		{ksealv1.TrustLevel_TRUST_LEVEL_MEDIUM_RISK, ksealv1.EnforcementMode_ENFORCEMENT_MODE_BLOCK, ksealv1.RequestProofResult_DECISION_STEP_UP},
		{ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED, ksealv1.EnforcementMode_ENFORCEMENT_MODE_BLOCK, ksealv1.RequestProofResult_DECISION_ALLOW},
	}
	for _, c := range cases {
		if got := Decision(c.level, c.mode); got != c.want {
			t.Errorf("Decision(%v,%v) = %v want %v", c.level, c.mode, got, c.want)
		}
	}
}

func TestNextChecksEscalates(t *testing.T) {
	if NextChecks(ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED) != nil {
		t.Fatal("trusted should need no extra checks")
	}
	if len(NextChecks(ksealv1.TrustLevel_TRUST_LEVEL_CRITICAL)) < len(NextChecks(ksealv1.TrustLevel_TRUST_LEVEL_MEDIUM_RISK)) {
		t.Fatal("higher risk should request at least as many checks")
	}
}
