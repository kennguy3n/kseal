package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManRootPageToStdout(t *testing.T) {
	cfg := t.TempDir() + "/config.json"
	out, _, code := runLocal(t, cfg, nil, "man")
	if code != ExitOK {
		t.Fatalf("man exit=%d", code)
	}
	if !strings.HasPrefix(out, ".TH \"KSEAL\"") {
		head := out
		if len(head) > 80 {
			head = head[:80]
		}
		t.Fatalf("man page should start with a .TH header, got:\n%s", head)
	}
	for _, want := range []string{".SH NAME", ".SH SYNOPSIS", ".SH COMMANDS"} {
		if !strings.Contains(out, want) {
			t.Fatalf("man page missing %s:\n%s", want, out)
		}
	}
}

func TestManTreeWritesPerCommandPages(t *testing.T) {
	cfg := t.TempDir() + "/config.json"
	dir := t.TempDir() + "/man"
	_, errOut, code := runLocal(t, cfg, nil, "man", "--dir", dir)
	if code != ExitOK {
		t.Fatalf("man --dir exit=%d err=%s", code, errOut)
	}
	// Spot-check that the guided commands each produced a page.
	for _, name := range []string{"kseal.1", "kseal-init.1", "kseal-doctor.1"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("expected man page %s: %v", name, err)
		}
		if !strings.Contains(string(data), ".TH") {
			t.Fatalf("%s is not a troff page:\n%s", name, data)
		}
	}
}

// TestManEscaping ensures troff control characters are neutralized.
func TestManEscaping(t *testing.T) {
	if got := manEscape("--dry-run"); got != "\\-\\-dry\\-run" {
		t.Fatalf("manEscape hyphens = %q", got)
	}
	if got := manEscape(".leading dot"); !strings.HasPrefix(got, "\\&") {
		t.Fatalf("manEscape should guard a leading dot, got %q", got)
	}
}
