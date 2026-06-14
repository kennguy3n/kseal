// Command privacy-manifest generates an Apple PrivacyInfo.xcprivacy manifest
// for the kseal SDK from the canonical, machine-readable SDK data contract.
//
// It is offline and zero-dependency: an integrator runs it in CI (or once at
// integration time) to drop an accurate privacy manifest into their iOS app
// target. The manifest falls out of the data contract, so it tracks what the
// SDK actually collects instead of being hand-maintained.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kennguy3n/kseal/tools/privacy-manifest/contract"
	"github.com/kennguy3n/kseal/tools/privacy-manifest/xcprivacy"
)

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "privacy-manifest: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr *os.File) error {
	fs := flag.NewFlagSet("privacy-manifest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	contractPath := fs.String("contract", "", "path to a data contract JSON (default: embedded canonical contract)")
	out := fs.String("out", "", "write the PrivacyInfo.xcprivacy to this path (default stdout)")
	outJSON := fs.String("out-json", "", "also write a JSON summary of the manifest to this path")
	includeOptional := fs.Bool("include-optional", false, "include data types that are off by default in the contract (e.g. coarse region)")
	quiet := fs.Bool("quiet", false, "suppress the human-readable summary line on stderr")
	showVersion := fs.Bool("version", false, "print the tool version and exit")
	fs.Usage = usageFunc(stderr, "privacy-manifest",
		"Generate an Apple PrivacyInfo.xcprivacy manifest for the kseal SDK from the canonical data contract.",
		fs,
		"  # Print the manifest to stdout",
		"  privacy-manifest",
		"",
		"  # Write the manifest and a JSON summary into an app target",
		"  privacy-manifest -out ios/App/PrivacyInfo.xcprivacy -out-json privacy-summary.json",
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Fprintf(stdout, "privacy-manifest %s\n", version)
		return nil
	}

	c, err := contract.Load(*contractPath)
	if err != nil {
		return err
	}
	manifest := xcprivacy.Generate(c, xcprivacy.Options{IncludeOptional: *includeOptional})

	xml := manifest.XML()
	if *out != "" {
		if err := writeFile(*out, xml); err != nil {
			return err
		}
	}
	if *outJSON != "" {
		data, jerr := jsonSummary(manifest)
		if jerr != nil {
			return jerr
		}
		if err := writeFile(*outJSON, data); err != nil {
			return err
		}
	}
	if *out == "" && *outJSON == "" {
		_, err = stdout.Write(xml)
		return err
	}
	if !*quiet {
		_, _ = fmt.Fprintf(stderr, "privacy-manifest: %d collected data type(s), %d required-reason API(s)\n",
			len(manifest.CollectedTypes), len(manifest.AccessedAPIs))
	}
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

// usageFunc builds a consistent --help renderer: a usage line, a one-line
// description, the flag defaults, and optional copy/paste examples. Keeping the
// shape identical across the compliance tools makes them feel like one suite.
func usageFunc(w *os.File, name, desc string, fs *flag.FlagSet, examples ...string) func() {
	return func() {
		_, _ = fmt.Fprintf(w, "Usage: %s [flags]\n\n%s\n\nFlags:\n", name, desc)
		fs.PrintDefaults()
		if len(examples) > 0 {
			_, _ = fmt.Fprintln(w, "\nExamples:")
			for _, ex := range examples {
				_, _ = fmt.Fprintln(w, ex)
			}
		}
	}
}
