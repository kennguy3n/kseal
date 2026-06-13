package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// JSON renders the report as indented, deterministic JSON.
func (r *Report) JSON() ([]byte, error) {
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", err)
	}
	return append(out, '\n'), nil
}

// Markdown renders a human-readable evidence report.
func (r *Report) Markdown() string {
	var b strings.Builder
	b.WriteString("# kseal — MASVS Evidence Report\n\n")
	b.WriteString(fmt.Sprintf("Generated %s by `%s`.\n\n", r.GeneratedAt, r.Generator))

	b.WriteString("## Build\n\n")
	b.WriteString("| Field | Value |\n|---|---|\n")
	writeRow(&b, "Platform", r.Manifest.Platform)
	writeRow(&b, "Schema", code(r.Manifest.Schema))
	writeRow(&b, "Build hash", code(r.Manifest.BuildHash))
	writeRow(&b, "SDK version", r.Manifest.SDKVersion)
	if r.Manifest.AppID != "" {
		writeRow(&b, "App", r.Manifest.AppID)
	}
	writeRow(&b, "Version", fmt.Sprintf("%s (%d)", r.Manifest.VersionName, r.Manifest.VersionCode))
	writeRow(&b, "Polymorphism seed", code(shortHash(r.Manifest.SeedDigest)))
	writeRow(&b, "Applied modules", code(strings.Join(r.Manifest.AppliedModules, ", ")))
	if r.Manifest.IntegritySlices > 0 {
		writeRow(&b, "Mach-O integrity slices", fmt.Sprintf("%d", r.Manifest.IntegritySlices))
	}
	b.WriteString("\n")

	b.WriteString("## Coverage Summary\n\n")
	b.WriteString(fmt.Sprintf("%d of %d catalog controls have build-time evidence in this release.\n\n",
		r.Summary.EvidencedControls, r.Summary.TotalControls))
	b.WriteString("| Status | Count |\n|---|---|\n")
	for _, s := range sortedStatuses(r.Summary.ByStatus) {
		writeRow(&b, statusLabel(s), fmt.Sprintf("%d", r.Summary.ByStatus[s]))
	}
	b.WriteString("\n")

	for _, c := range r.Categories {
		b.WriteString(fmt.Sprintf("## %s\n\n", c.Name))
		if c.Objective != "" {
			b.WriteString(fmt.Sprintf("_%s_\n\n", c.Objective))
		}
		b.WriteString(fmt.Sprintf("Build-time evidenced: %d / %d.\n\n", c.EvidenceHit, len(c.Controls)))
		b.WriteString("| MASVS objective | kseal control | Phase | Status | Evidence |\n|---|---|---|---|---|\n")
		for _, ctl := range c.Controls {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
				escape(ctl.Objective), escape(ctl.Control), escape(ctl.Phase),
				statusLabel(ctl.Evidence.Status), escape(ctl.Evidence.Detail)))
		}
		b.WriteString("\n")
	}

	if len(r.Orphans) > 0 {
		b.WriteString("## Orphaned Evidence\n\n")
		b.WriteString("Build-proof evidence whose target catalog control was not found (the mapping doc and the plugins may have drifted):\n\n")
		b.WriteString("| Category | Expected control | Status | Evidence |\n|---|---|---|---|\n")
		for _, o := range r.Orphans {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
				escape(o.Category), escape(o.Expected), statusLabel(o.Evidence.Status), escape(o.Evidence.Detail)))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func writeRow(b *strings.Builder, k, v string) { b.WriteString(fmt.Sprintf("| %s | %s |\n", k, v)) }

func code(s string) string {
	if s == "" {
		return ""
	}
	return "`" + s + "`"
}

// escape neutralizes pipe characters so cell content cannot break the table.
func escape(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

func statusLabel(status string) string {
	switch status {
	case StatusEvidenced:
		return "evidenced"
	case StatusPartial:
		return "partial"
	case StatusSkipped:
		return "skipped (reported)"
	case StatusAbsent:
		return "not in this build"
	case StatusNotApplicable:
		return "n/a (platform)"
	case StatusInformational:
		return "other plane"
	default:
		return status
	}
}

func sortedStatuses(m map[string]int) []string {
	order := map[string]int{
		StatusEvidenced: 0, StatusPartial: 1, StatusSkipped: 2,
		StatusAbsent: 3, StatusNotApplicable: 4, StatusInformational: 5,
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		oi, oj := order[keys[i]], order[keys[j]]
		if oi != oj {
			return oi < oj
		}
		return keys[i] < keys[j]
	})
	return keys
}
