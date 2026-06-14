package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// newManCmd generates troff man pages for the whole command tree. It is written
// without an external markdown/man converter so the CLI stays dependency-light
// and the output is deterministic (no build-host fonts or dates leaking in).
//
// Typical use:
//
//	kseal man --dir ./man && sudo cp ./man/*.1 /usr/local/share/man/man1/
func newManCmd(c *CLI) *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "man",
		Short: "Generate troff man pages for kseal and its subcommands",
		Long: "Generate section-1 man pages (one per command) for offline reference and " +
			"distribution packaging. With --dir the pages are written there as <command>.1; " +
			"without it, the root page is written to stdout so it can be piped to `man -l -`.",
		Example: "  # Write the full set into ./man\n" +
			"  kseal man --dir ./man\n\n" +
			"  # Preview the top-level page\n" +
			"  kseal man | man -l -",
		Annotations: map[string]string{annotationLocalOnly: "true"},
		// Hidden from the primary command list: it is a packaging/tooling aid,
		// discoverable via `kseal help man` but not noise for everyday users.
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			root := cmd.Root()
			if dir == "" {
				return writeManPage(c.out, root)
			}
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("create man dir: %w", err)
			}
			count, err := writeManTree(dir, root)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.errOut, "wrote %d man page(s) to %s\n", count, dir)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "output directory for generated man pages (default: stdout for the root page)")
	return cmd
}

// writeManTree renders one page per non-hidden command in the tree, returning
// the number of pages written.
func writeManTree(dir string, cmd *cobra.Command) (int, error) {
	count := 0
	for _, sub := range cmd.Commands() {
		if !sub.IsAvailableCommand() || sub.IsAdditionalHelpTopicCommand() {
			continue
		}
		n, err := writeManTree(dir, sub)
		if err != nil {
			return count, err
		}
		count += n
	}
	name := strings.ReplaceAll(cmd.CommandPath(), " ", "-")
	f, err := os.Create(filepath.Join(dir, name+".1"))
	if err != nil {
		return count, fmt.Errorf("create man page: %w", err)
	}
	defer f.Close()
	if err := writeManPage(f, cmd); err != nil {
		return count, err
	}
	return count + 1, nil
}

// manDate is fixed to a stable value so generated pages are byte-deterministic
// (important for reproducible packaging and golden tests). Distributors that
// want a build date can post-process the .TH line.
var manDate = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

// writeManPage renders a single command as a troff(1) man page.
func writeManPage(w io.Writer, cmd *cobra.Command) error {
	path := cmd.CommandPath()
	title := strings.ToUpper(strings.ReplaceAll(path, " ", "-"))
	var b strings.Builder

	fmt.Fprintf(&b, ".TH \"%s\" \"1\" \"%s\" \"%s\" \"kseal Manual\"\n",
		title, manDate.Format("January 2006"), "kseal "+version)

	b.WriteString(".SH NAME\n")
	fmt.Fprintf(&b, "%s \\- %s\n", manEscape(path), manEscape(cmd.Short))

	b.WriteString(".SH SYNOPSIS\n")
	fmt.Fprintf(&b, ".B %s\n", manEscape(cmd.UseLine()))

	if desc := cmd.Long; desc != "" {
		b.WriteString(".SH DESCRIPTION\n")
		b.WriteString(manParagraphs(desc))
	} else if cmd.Short != "" {
		b.WriteString(".SH DESCRIPTION\n")
		fmt.Fprintf(&b, "%s\n", manEscape(cmd.Short))
	}

	writeManFlags(&b, "OPTIONS", cmd.NonInheritedFlags())
	writeManFlags(&b, "GLOBAL OPTIONS", cmd.InheritedFlags())

	if ex := cmd.Example; ex != "" {
		b.WriteString(".SH EXAMPLES\n")
		b.WriteString(manExample(ex))
	}

	if sub := availableSubcommands(cmd); len(sub) > 0 {
		b.WriteString(".SH COMMANDS\n")
		for _, s := range sub {
			fmt.Fprintf(&b, ".TP\n.B %s\n%s\n", manEscape(s.Name()), manEscape(s.Short))
		}
	}

	b.WriteString(".SH SEE ALSO\n")
	seeAlso := manSeeAlso(cmd)
	if seeAlso == "" {
		seeAlso = "kseal documentation at docs/cli.md"
	}
	b.WriteString(seeAlso + "\n")

	_, err := io.WriteString(w, b.String())
	return err
}

func availableSubcommands(cmd *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	for _, s := range cmd.Commands() {
		if s.IsAvailableCommand() && !s.IsAdditionalHelpTopicCommand() {
			out = append(out, s)
		}
	}
	return out
}

// manSeeAlso links the parent and immediate children as man-page cross refs.
func manSeeAlso(cmd *cobra.Command) string {
	var refs []string
	if cmd.HasParent() {
		refs = append(refs, manRef(cmd.Parent()))
	}
	for _, s := range availableSubcommands(cmd) {
		refs = append(refs, manRef(s))
	}
	return strings.Join(refs, ",\n")
}

func manRef(cmd *cobra.Command) string {
	name := strings.ReplaceAll(cmd.CommandPath(), " ", "-")
	return fmt.Sprintf(".BR %s (1)", manEscape(name))
}

// writeManFlags emits a flag section if the set is non-empty.
func writeManFlags(b *strings.Builder, heading string, flags *pflag.FlagSet) {
	if !flags.HasAvailableFlags() {
		return
	}
	fmt.Fprintf(b, ".SH %s\n", heading)
	flags.VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		var head strings.Builder
		if f.Shorthand != "" {
			fmt.Fprintf(&head, "\\fB\\-%s\\fR, ", manEscape(f.Shorthand))
		}
		fmt.Fprintf(&head, "\\fB\\-\\-%s\\fR", manEscape(f.Name))
		if f.Value.Type() != "bool" {
			fmt.Fprintf(&head, " \\fI%s\\fR", f.Value.Type())
		}
		usage := f.Usage
		if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" && f.DefValue != "0s" {
			usage = fmt.Sprintf("%s (default %s)", usage, f.DefValue)
		}
		fmt.Fprintf(b, ".TP\n%s\n%s\n", head.String(), manEscape(usage))
	})
}

// manParagraphs renders blank-line-separated paragraphs with a .PP break.
func manParagraphs(s string) string {
	parts := strings.Split(strings.TrimSpace(s), "\n\n")
	var b strings.Builder
	for i, p := range parts {
		if i > 0 {
			b.WriteString(".PP\n")
		}
		b.WriteString(manEscape(strings.ReplaceAll(p, "\n", " ")) + "\n")
	}
	return b.String()
}

// manExample renders example text verbatim inside a no-fill block so the
// command lines keep their layout.
func manExample(s string) string {
	var b strings.Builder
	b.WriteString(".nf\n")
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString(manEscape(line) + "\n")
	}
	b.WriteString(".fi\n")
	return b.String()
}

// manUnicode maps the non-ASCII punctuation used in command copy to troff
// escapes/ASCII so pages render correctly under any locale (man -Tascii cannot
// display raw UTF-8). Applied last, after backslash/hyphen escaping, because the
// replacements themselves contain intentional troff backslashes.
var manUnicode = strings.NewReplacer(
	"—", "\\(em", // em dash
	"–", "\\(en", // en dash
	"→", "\\(->", // right arrow
	"…", "...", // ellipsis
	"“", "\\(lq", "”", "\\(rq", // curly double quotes
	"‘", "`", "’", "'", // curly single quotes
)

// manEscape escapes the troff control characters that would otherwise corrupt a
// man page: backslashes, leading dots/apostrophes (control lines), and hyphens
// (rendered as minus signs), then normalizes non-ASCII punctuation.
func manEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "-", "\\-")
	// A line beginning with '.' or '\'' is a troff request; guard it with the
	// zero-width "\&" so literal text starting that way is printed.
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "'") {
		s = "\\&" + s
	}
	return manUnicode.Replace(s)
}
