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

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "dev"

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
	quiet := fs.Bool("quiet", false, "suppress the human-readable summary line on stderr")
	showVersion := fs.Bool("version", false, "print the tool version and exit")
	fs.Usage = usageFunc(stderr, "datasafety",
		"Generate Google Play Console Data-Safety form answers for the kseal SDK from the canonical data contract.",
		fs,
		"  # Print the Markdown summary to stdout",
		"  datasafety",
		"",
		"  # Emit the machine-readable form for CI diffing",
		"  datasafety -out-json data-safety.json -out-md data-safety.md",
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Fprintf(stdout, "datasafety %s\n", version)
		return nil
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
	if !*quiet {
		_, _ = fmt.Fprintf(stderr, "datasafety: %d data type(s) collected, shares=%t, encrypted-in-transit=%t\n",
			len(form.DataTypes), form.SharesData, form.EncryptedInTransit)
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
