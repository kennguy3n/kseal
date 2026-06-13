// Command datasafety generates Google Play Console Data-Safety form answers for
// the kseal SDK from the canonical, machine-readable SDK data contract.
//
// It emits a machine-readable JSON form and/or a human-readable Markdown
// summary, so an integrator can answer the Play Console questionnaire (and diff
// it in CI) instead of hand-maintaining it.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kennguy3n/kseal/tools/datasafety/datasafety"
	"github.com/kennguy3n/kseal/tools/privacy-manifest/contract"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "datasafety: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr *os.File) error {
	fs := flag.NewFlagSet("datasafety", flag.ContinueOnError)
	fs.SetOutput(stderr)
	contractPath := fs.String("contract", "", "path to a data contract JSON (default: embedded canonical contract)")
	outJSON := fs.String("out-json", "", "write the machine-readable Data-Safety form to this path")
	outMD := fs.String("out-md", "", "write the human-readable Markdown summary to this path (default stdout)")
	includeOptional := fs.Bool("include-optional", false, "include data types that are off by default in the contract (e.g. coarse region)")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: datasafety [flags]")
		_, _ = fmt.Fprintln(stderr, "Generate Google Play Data-Safety form answers for the kseal SDK from the data contract.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := contract.Load(*contractPath)
	if err != nil {
		return err
	}
	form := datasafety.Generate(c, datasafety.Options{IncludeOptional: *includeOptional})

	if *outJSON != "" {
		data, jerr := form.JSON()
		if jerr != nil {
			return jerr
		}
		if err := writeFile(*outJSON, data); err != nil {
			return err
		}
	}
	// Render Markdown only when it will actually be consumed: written to --out-md,
	// or printed to stdout as the default human-readable output.
	switch {
	case *outMD != "":
		if err := writeFile(*outMD, form.Markdown()); err != nil {
			return err
		}
	case *outJSON == "":
		if _, err := stdout.Write(form.Markdown()); err != nil {
			return err
		}
		return nil
	}
	_, _ = fmt.Fprintf(stderr, "datasafety: %d data type(s) collected, shares=%t, encrypted-in-transit=%t\n",
		len(form.DataTypes), form.SharesData, form.EncryptedInTransit)
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
