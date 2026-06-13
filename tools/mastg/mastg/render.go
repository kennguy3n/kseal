package mastg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// JSON renders the report as deterministic, indented JSON.
func (r *Report) JSON() ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Markdown renders a human-readable per-release report: a header with release
// metadata, a status summary, and a per-category table of procedures.
func (r *Report) Markdown() []byte {
	var b strings.Builder
	b.WriteString("# kseal MASTG verification report\n\n")
	if r.Release != "" || r.Platform != "" || r.BuildHash != "" {
		if r.Release != "" {
			fmt.Fprintf(&b, "- Release: `%s`\n", r.Release)
		}
		if r.Platform != "" {
			fmt.Fprintf(&b, "- Platform: `%s`\n", r.Platform)
		}
		if r.BuildHash != "" {
			fmt.Fprintf(&b, "- Build hash: `%s`\n", r.BuildHash)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Summary\n\n")
	b.WriteString("| Status | Count |\n|---|---|\n")
	for _, s := range r.SortedSummary() {
		fmt.Fprintf(&b, "| %s | %d |\n", s.Status, s.Count)
	}
	fmt.Fprintf(&b, "\n%s\n\n", gatingLine(r.Gating))

	b.WriteString("## Procedures\n\n")
	var lastCat string
	for _, res := range r.Results {
		if res.Procedure.Category != lastCat {
			if lastCat != "" {
				b.WriteString("\n")
			}
			fmt.Fprintf(&b, "### %s\n\n", res.Procedure.Category)
			b.WriteString("| Objective | Status | Method | Plane | Notes |\n")
			b.WriteString("|---|---|---|---|---|\n")
			lastCat = res.Procedure.Category
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
			res.Procedure.Objective, res.Status,
			res.Procedure.Method,
			res.Procedure.Plane, oneLine(res.Note))
	}
	return []byte(b.String())
}

func gatingLine(g GatingSummary) string {
	if g.Blocked {
		if g.Failed > 0 {
			return fmt.Sprintf("**Release blocked:** %d failed procedure(s): %s", g.Failed, strings.Join(g.FailedIDs, ", "))
		}
		return fmt.Sprintf("**Release blocked (require-pass):** %d pending procedure(s).", g.Pending)
	}
	if g.Failed == 0 {
		return "**No failing procedures.**"
	}
	return ""
}

func oneLine(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
}
