// Command mastg maps the kseal MASVS control catalog (docs/masvs-mapping.md) to
// OWASP MASTG verification procedures and emits a per-release pass/observed
// report. It complements tools/masvs-report: that tool overlays build-proof
// evidence onto MASVS coverage; this one tracks the MASTG verification
// procedures and their run status, optionally ingesting a masvs-report JSON and
// explicit device-test assertions as evidence.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kennguy3n/kseal/tools/mastg/mastg"
)

// exit codes: 0 ok, 1 runtime error, 2 usage error, 3 release blocked.
const (
	exitErr     = 1
	exitBlocked = 3
)

func main() {
	code, err := run(os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mastg: "+err.Error())
	}
	os.Exit(code)
}

func run(args []string, stdout, stderr *os.File) (int, error) {
	fs := flag.NewFlagSet("mastg", flag.ContinueOnError)
	fs.SetOutput(stderr)
	catalogPath := fs.String("catalog", "docs/masvs-mapping.md", "path to the MASVS control catalog markdown")
	evidencePath := fs.String("evidence", "", "path to a per-release evidence JSON (explicit MASTG assertions)")
	masvsReportPath := fs.String("masvs-report", "", "path to a tools/masvs-report JSON to overlay as build evidence")
	format := fs.String("format", "table", "output format: table|json")
	out := fs.String("out", "", "write report to this path (default stdout)")
	requirePass := fs.Bool("require-pass", false, "strict mode: pending device procedures also block the release")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: mastg [flags]")
		_, _ = fmt.Fprintln(stderr, "Run kseal MASTG verification procedures against per-release evidence.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitErr, nil // flag already printed the error/usage
	}
	if *format != "table" && *format != "json" {
		return exitErr, fmt.Errorf("invalid -format %q (want table|json)", *format)
	}

	resolved, err := locateCatalog(*catalogPath)
	if err != nil {
		return exitErr, err
	}
	md, err := os.ReadFile(resolved)
	if err != nil {
		return exitErr, fmt.Errorf("read catalog: %w", err)
	}
	cat, err := mastg.ParseCatalog(string(md))
	if err != nil {
		return exitErr, err
	}

	ev := &mastg.Evidence{}
	if *evidencePath != "" {
		data, rerr := os.ReadFile(*evidencePath)
		if rerr != nil {
			return exitErr, fmt.Errorf("read evidence: %w", rerr)
		}
		if ev, err = mastg.LoadEvidence(data); err != nil {
			return exitErr, err
		}
	}
	if *masvsReportPath != "" {
		data, rerr := os.ReadFile(*masvsReportPath)
		if rerr != nil {
			return exitErr, fmt.Errorf("read masvs-report: %w", rerr)
		}
		if err := ev.MergeMASVSReport(data); err != nil {
			return exitErr, err
		}
	}

	report := cat.Run(ev, mastg.RunOptions{RequirePass: *requirePass})

	var rendered []byte
	if *format == "json" {
		if rendered, err = report.JSON(); err != nil {
			return exitErr, err
		}
	} else {
		rendered = report.Markdown()
	}
	if *out != "" {
		if err := writeFile(*out, rendered); err != nil {
			return exitErr, err
		}
	} else if _, err := stdout.Write(rendered); err != nil {
		return exitErr, err
	}

	if report.Gating.Blocked {
		_, _ = fmt.Fprintf(stderr, "mastg: release blocked (failed=%d pending=%d)\n", report.Gating.Failed, report.Gating.Pending)
		return exitBlocked, nil
	}
	return 0, nil
}

// locateCatalog returns the path as-is if it exists, otherwise walks up from the
// working directory to find it, so the tool works from any subdirectory of the
// repo without configuration.
func locateCatalog(path string) (string, error) {
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	if filepath.IsAbs(path) {
		return "", fmt.Errorf("catalog not found: %s", path)
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(dir, path)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("catalog not found searching up from working dir: %s", path)
		}
		dir = parent
	}
}

func writeFile(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
