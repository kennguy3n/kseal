// Command masvs-report generates a per-release MASVS evidence report from a
// kseal build-proof manifest and the MASVS control catalog (docs/masvs-mapping.md).
//
// It is intentionally zero-dependency and offline: it reads the manifest that
// the Gradle/Xcode plugins already emit (the same document registered via
// RegistryService.CreateBuild) and the checked-in catalog, then writes a
// Markdown and/or JSON report. This keeps it NoOps-friendly and safe to run in
// any CI step after hardening.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kennguy3n/kseal/tools/masvs-report/internal/buildproof"
	"github.com/kennguy3n/kseal/tools/masvs-report/internal/catalog"
	"github.com/kennguy3n/kseal/tools/masvs-report/internal/report"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "masvs-report: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("masvs-report", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "path to the build-proof manifest JSON (required)")
	catalogPath := fs.String("catalog", "docs/masvs-mapping.md", "path to the MASVS control catalog markdown")
	outMarkdown := fs.String("out-md", "", "write the Markdown report to this path (default stdout)")
	outJSON := fs.String("out-json", "", "write the JSON report to this path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" {
		return fmt.Errorf("missing required -manifest")
	}

	manifestBytes, err := os.ReadFile(*manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	manifest, err := buildproof.Parse(manifestBytes)
	if err != nil {
		return err
	}

	catalogBytes, err := os.ReadFile(*catalogPath)
	if err != nil {
		return fmt.Errorf("read catalog: %w", err)
	}
	cat, err := catalog.Parse(string(catalogBytes))
	if err != nil {
		return err
	}

	rep := report.New().Generate(manifest, cat)

	if *outJSON != "" {
		data, err := rep.JSON()
		if err != nil {
			return err
		}
		if err := writeFile(*outJSON, data); err != nil {
			return err
		}
	}

	md := []byte(rep.Markdown())
	if *outMarkdown != "" {
		if err := writeFile(*outMarkdown, md); err != nil {
			return err
		}
	}
	if *outMarkdown == "" && *outJSON == "" {
		_, err = os.Stdout.Write(md)
		return err
	}
	fmt.Fprintf(os.Stderr, "masvs-report: %d/%d controls evidenced for %s build %s\n",
		rep.Summary.EvidencedControls, rep.Summary.TotalControls, manifest.Platform, shortID(manifest.BuildHash))
	return nil
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

func shortID(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
