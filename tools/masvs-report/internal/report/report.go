// Package report overlays build-proof evidence onto the MASVS control catalog
// and renders a per-release evidence report (JSON + Markdown).
//
// Evidence rules connect concrete build-proof signals (applied transforms, the
// polymorphism seed, Mach-O integrity slices) to specific catalog controls. A
// control with a rule reflects the *real* manifest data for this build; controls
// without a rule are listed honestly as out-of-scope for the build plane
// (runtime/server/tenant responsibility), matching the catalog's framing that
// the authoritative decision is server-side.
package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kennguy3n/kseal/tools/masvs-report/internal/buildproof"
	"github.com/kennguy3n/kseal/tools/masvs-report/internal/catalog"
)

// Evidence status values.
const (
	StatusEvidenced     = "evidenced"      // build-proof proves the control for this build
	StatusPartial       = "partial"        // some, but not full, build-time evidence
	StatusSkipped       = "skipped"        // step ran but had nothing to act on (reported, not silent)
	StatusAbsent        = "absent"         // a build-plane control with no evidence in this build
	StatusNotApplicable = "not-applicable" // build-plane control that does not apply to this platform
	StatusInformational = "informational"  // owned by another plane (runtime/server/tenant)
)

// Report is the structured, serializable evidence report.
type Report struct {
	GeneratedAt string           `json:"generatedAt"`
	Generator   string           `json:"generator"`
	Manifest    ManifestSummary  `json:"manifest"`
	Categories  []CategoryReport `json:"categories"`
	Orphans     []Orphan         `json:"orphanEvidence,omitempty"`
	Summary     Summary          `json:"summary"`
}

// ManifestSummary echoes the build-proof identity the report was generated from.
type ManifestSummary struct {
	Schema          string   `json:"schema"`
	Platform        string   `json:"platform"`
	BuildHash       string   `json:"buildHash"`
	SDKVersion      string   `json:"sdkVersion"`
	AppID           string   `json:"appId,omitempty"`
	VersionName     string   `json:"versionName"`
	VersionCode     int64    `json:"versionCode"`
	SeedDigest      string   `json:"seedDigest"`
	AppliedModules  []string `json:"appliedModules"`
	IntegritySlices int      `json:"integritySlices"`
}

// CategoryReport is one MASVS category with its evaluated controls.
type CategoryReport struct {
	Name        string          `json:"name"`
	Objective   string          `json:"objective,omitempty"`
	Controls    []ControlReport `json:"controls"`
	EvidenceHit int             `json:"evidencedControls"`
}

// ControlReport is one catalog control plus its evaluated evidence.
type ControlReport struct {
	Objective string   `json:"objective"`
	Control   string   `json:"ksealControl"`
	Module    string   `json:"module"`
	MASTG     string   `json:"mastg"`
	Evidence  Evidence `json:"evidence"`
}

// Evidence is the verdict for a control against this build's manifest.
type Evidence struct {
	Status string `json:"status"`
	Source string `json:"source,omitempty"`
	Detail string `json:"detail"`
}

// Orphan is build-proof evidence whose target catalog control was not found
// (e.g. the control was renamed/removed in the mapping doc). Surfacing it keeps
// the report honest when the catalog and the plugins drift apart.
type Orphan struct {
	Category string   `json:"category"`
	Expected string   `json:"expectedControl"`
	Evidence Evidence `json:"evidence"`
}

// Summary aggregates coverage counts.
type Summary struct {
	TotalControls     int            `json:"totalControls"`
	EvidencedControls int            `json:"evidencedControls"`
	ByStatus          map[string]int `json:"byStatus"`
}

// Generator builds reports from a manifest and catalog at a fixed time.
type Generator struct {
	Now func() time.Time
}

// New returns a Generator using the real clock.
func New() *Generator { return &Generator{Now: func() time.Time { return time.Now().UTC() }} }

// rule binds a manifest evaluator to a catalog control, matched by category and
// a stable substring of the control's MASVS-objective column.
type rule struct {
	category     string
	objectiveSub string
	eval         func(*buildproof.Manifest) Evidence
}

func rules() []rule {
	return []rule{
		{"MASVS-RESILIENCE", "Obfuscation + polymorphism", evalObfuscation},
		{"MASVS-RESILIENCE", "Anti-tamper / integrity", evalIntegrity},
		{"MASVS-CODE", "Memory safety in native", evalNativeMemory},
		{"MASVS-CODE", "Build provenance", evalProvenance},
		{"MASVS-STORAGE", "No secrets in app storage", evalNoStaticSecrets},
	}
}

// Generate overlays the manifest's evidence onto the catalog.
func (g *Generator) Generate(m *buildproof.Manifest, cat *catalog.Catalog) *Report {
	rep := &Report{
		GeneratedAt: g.Now().Format(time.RFC3339),
		Generator:   "kseal-masvs-report/0.1.0",
		Manifest:    summarize(m),
		Summary:     Summary{ByStatus: map[string]int{}},
	}

	// Index rules by category for ordered application.
	byCategory := map[string][]rule{}
	for _, r := range rules() {
		byCategory[r.category] = append(byCategory[r.category], r)
	}

	for _, c := range cat.Categories {
		cr := CategoryReport{Name: c.Name, Objective: c.Objective}
		matched := map[int]Evidence{} // control index -> evidence from its rule

		// Apply each rule once. A rule whose target control is absent from the
		// catalog surfaces as an orphan; otherwise its evidence is cached by
		// control index (eval funcs are pure, so one call is enough).
		for _, r := range byCategory[c.Name] {
			ev := r.eval(m)
			idx := indexOfControl(c.Controls, r.objectiveSub)
			if idx < 0 {
				rep.Orphans = append(rep.Orphans, Orphan{Category: c.Name, Expected: r.objectiveSub, Evidence: ev})
				continue
			}
			matched[idx] = ev
		}

		for i, ctl := range c.Controls {
			ev, ok := matched[i]
			if !ok {
				ev = Evidence{Status: StatusInformational, Detail: "owned by another plane (runtime/server/tenant); not evidenced by the build proof"}
			}
			cr.Controls = append(cr.Controls, ControlReport{
				Objective: ctl.Objective,
				Control:   ctl.Control,
				Module:    ctl.Module,
				MASTG:     ctl.MASTG,
				Evidence:  ev,
			})
			rep.Summary.ByStatus[ev.Status]++
			rep.Summary.TotalControls++
			if ev.Status == StatusEvidenced {
				cr.EvidenceHit++
				rep.Summary.EvidencedControls++
			}
		}
		rep.Categories = append(rep.Categories, cr)
	}
	return rep
}

func indexOfControl(controls []catalog.Control, objectiveSub string) int {
	for i, c := range controls {
		if strings.Contains(c.Objective, objectiveSub) {
			return i
		}
	}
	return -1
}

func summarize(m *buildproof.Manifest) ManifestSummary {
	applied := []string{}
	for _, t := range m.Transforms {
		if t.Applied() {
			applied = append(applied, t.Name)
		}
	}
	sort.Strings(applied)
	slices := 0
	if m.Integrity != nil {
		slices = len(m.Integrity.Slices)
	}
	return ManifestSummary{
		Schema:          m.Schema,
		Platform:        m.Platform,
		BuildHash:       m.BuildHash,
		SDKVersion:      m.SDKVersion,
		AppID:           m.AppID,
		VersionName:     m.VersionName,
		VersionCode:     m.VersionCode,
		SeedDigest:      m.SeedDigest,
		AppliedModules:  applied,
		IntegritySlices: slices,
	}
}

// MARK: - Evidence evaluators

var obfuscationTransforms = []string{"string-obfuscation", "string-resource-seal", "symbol-strip", "strip-debug-metadata"}

func evalObfuscation(m *buildproof.Manifest) Evidence {
	var applied []string
	for _, name := range obfuscationTransforms {
		if m.HasAppliedTransform(name) {
			applied = append(applied, name)
		}
	}
	poly := m.SeedDigest != "" || m.HasAppliedTransform("polymorphism")
	switch {
	case len(applied) > 0 && poly:
		return Evidence{Status: StatusEvidenced, Source: "build-proof",
			Detail: fmt.Sprintf("obfuscation transforms applied [%s]; per-build polymorphism seed %s (%s)",
				strings.Join(applied, ", "), shortHash(m.SeedDigest), orNone(m.SeedAlgorithm))}
	case len(applied) > 0:
		return Evidence{Status: StatusPartial, Source: "build-proof",
			Detail: fmt.Sprintf("obfuscation transforms applied [%s] but no polymorphism seed recorded", strings.Join(applied, ", "))}
	case poly:
		return Evidence{Status: StatusPartial, Source: "build-proof",
			Detail: fmt.Sprintf("per-build polymorphism seed %s recorded but no obfuscation transform applied", shortHash(m.SeedDigest))}
	default:
		return Evidence{Status: StatusAbsent, Source: "build-proof", Detail: "no obfuscation or polymorphism evidence in this build"}
	}
}

func evalIntegrity(m *buildproof.Manifest) Evidence {
	if m.Integrity != nil && len(m.Integrity.Slices) > 0 {
		var archs []string
		for _, s := range m.Integrity.Slices {
			archs = append(archs, s.Arch)
		}
		return Evidence{Status: StatusEvidenced, Source: "build-proof",
			Detail: fmt.Sprintf("Mach-O section-hash integrity baked for %d slice(s) [%s]; load-command hashes recorded for runtime tamper detection",
				len(m.Integrity.Slices), strings.Join(archs, ", "))}
	}
	if m.HasAppliedTransform("native-library-harden") {
		return Evidence{Status: StatusEvidenced, Source: "build-proof",
			Detail: fmt.Sprintf("native libraries hashed into the build proof; build_hash %s binds all artifacts for tamper detection", shortHash(m.BuildHash))}
	}
	if m.BuildHash != "" {
		return Evidence{Status: StatusPartial, Source: "build-proof",
			Detail: fmt.Sprintf("build_hash %s binds the manifest's artifacts, but no per-section integrity baked for this build", shortHash(m.BuildHash))}
	}
	return Evidence{Status: StatusAbsent, Source: "build-proof", Detail: "no integrity binding recorded"}
}

func evalNativeMemory(m *buildproof.Manifest) Evidence {
	t, ok := m.Transform("native-library-harden")
	if !ok {
		if m.Platform == "ios" {
			return Evidence{Status: StatusNotApplicable, Source: "build-proof",
				Detail: "no native .so plane on iOS; native memory safety is provided by the audited Rust core, not recorded as a build transform"}
		}
		return Evidence{Status: StatusAbsent, Source: "build-proof", Detail: "no native libraries hardened/verified in this build"}
	}
	if !t.Applied() {
		return Evidence{Status: StatusSkipped, Source: "build-proof",
			Detail: "native hardening ran but found no libraries to verify (reported, not silently skipped)"}
	}
	summary := nestedMap(t.Detail, "summary")
	cfiEnabled := mapInt(summary, "cfi_enabled")
	cfiAbsent := mapInt(summary, "cfi_absent")
	cfiUnsupported := mapInt(summary, "cfi_unsupported")
	mteEnabled := mapInt(summary, "mte_enabled")
	mteUnsupported := mapInt(summary, "mte_unsupported")
	libs := t.Count
	return Evidence{Status: StatusEvidenced, Source: "build-proof",
		Detail: fmt.Sprintf("verified %d native library(ies): CFI enabled=%d absent=%d unsupported=%d; MTE enabled=%d unsupported=%d (unsupported targets reported, not skipped)",
			libs, cfiEnabled, cfiAbsent, cfiUnsupported, mteEnabled, mteUnsupported)}
}

func evalProvenance(m *buildproof.Manifest) Evidence {
	if m.BuildHash == "" || m.Schema == "" {
		return Evidence{Status: StatusAbsent, Source: "build-proof", Detail: "no build hash / schema recorded"}
	}
	return Evidence{Status: StatusEvidenced, Source: "build-proof",
		Detail: fmt.Sprintf("build proof %q with build_hash %s records %d transform(s); registrable via RegistryService.CreateBuild for runtime verification",
			m.Schema, shortHash(m.BuildHash), len(m.Transforms))}
}

func evalNoStaticSecrets(m *buildproof.Manifest) Evidence {
	var applied []string
	count := 0
	for _, name := range []string{"string-obfuscation", "string-resource-seal"} {
		if t, ok := m.Transform(name); ok && t.Applied() {
			applied = append(applied, name)
			count += t.Count
		}
	}
	if len(applied) == 0 {
		return Evidence{Status: StatusAbsent, Source: "build-proof", Detail: "no string-sealing transform applied; cannot assert absence of static secrets from the build proof alone"}
	}
	detail := fmt.Sprintf("string sealing applied [%s]; flagged secrets/strings are encrypted, not shipped as plaintext", strings.Join(applied, ", "))
	if count > 0 {
		detail = fmt.Sprintf("%d string(s) sealed [%s]; flagged secrets are encrypted, not shipped as plaintext", count, strings.Join(applied, ", "))
	}
	return Evidence{Status: StatusEvidenced, Source: "build-proof", Detail: detail}
}

// MARK: - small helpers

func shortHash(h string) string {
	if len(h) <= 12 {
		return orNone(h)
	}
	return h[:12] + "…"
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func nestedMap(detail map[string]any, key string) map[string]any {
	if v, ok := detail[key]; ok {
		if m, ok := v.(map[string]any); ok {
			return m
		}
	}
	return nil
}

func mapInt(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	switch n := m[key].(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}
