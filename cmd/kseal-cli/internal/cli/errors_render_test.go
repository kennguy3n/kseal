package cli

import (
	"strings"
	"testing"
)

func TestRenderErrorPlain(t *testing.T) {
	var b strings.Builder
	renderError(&b, withHint(newUsageError("no tenant scope"), "pass --tenant <id>"), false)
	got := b.String()
	if !strings.Contains(got, "error: no tenant scope") {
		t.Fatalf("missing error line:\n%s", got)
	}
	if !strings.Contains(got, "hint: pass --tenant <id>") {
		t.Fatalf("missing hint line:\n%s", got)
	}
	if strings.Contains(got, "debug:") {
		t.Fatalf("plain render must not include debug lines:\n%s", got)
	}
}

func TestRenderErrorDebugAddsDiagnostics(t *testing.T) {
	var b strings.Builder
	renderError(&b, newAuthError("bad key"), true)
	got := b.String()
	if !strings.Contains(got, "debug: exit code 3") {
		t.Fatalf("debug render should include the exit code:\n%s", got)
	}
}

func TestRenderErrorNil(t *testing.T) {
	var b strings.Builder
	renderError(&b, nil, true)
	if b.String() != "" {
		t.Fatalf("nil error should render nothing, got %q", b.String())
	}
}

// TestHintPreservesExitClass ensures wrapping an error with a hint does not
// change its exit-code classification.
func TestHintPreservesExitClass(t *testing.T) {
	if code := ExitCode(withHint(newUsageError("x"), "do y")); code != ExitUsage {
		t.Fatalf("hinted usage error exit = %d, want %d", code, ExitUsage)
	}
	if code := ExitCode(withHint(newAuthError("x"), "do y")); code != ExitAuth {
		t.Fatalf("hinted auth error exit = %d, want %d", code, ExitAuth)
	}
}
