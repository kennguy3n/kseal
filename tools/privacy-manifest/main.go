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
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: privacy-manifest [flags]")
		_, _ = fmt.Fprintln(stderr, "Generate an Apple PrivacyInfo.xcprivacy for the kseal SDK from the data contract.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
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
	_, _ = fmt.Fprintf(stderr, "privacy-manifest: %d collected data type(s), %d required-reason API(s)\n",
		len(manifest.CollectedTypes), len(manifest.AccessedAPIs))
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
