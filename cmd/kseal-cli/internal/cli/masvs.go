package cli

import (
	"encoding/json"
	"sort"
	"strings"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// masvsCategories is the ordered set of OWASP MASVS categories the report maps
// the protected build's modules onto. Order mirrors docs/masvs-mapping.md so
// the report reads like the canonical mapping doc.
var masvsCategories = []string{
	"STORAGE", "CRYPTO", "AUTH", "NETWORK", "PLATFORM", "CODE", "RESILIENCE", "PRIVACY",
}

// moduleMASVS maps a hardening/RASP module (as named in a build manifest) to the
// MASVS categories it contributes evidence toward. Keys are normalized
// (lower-case, non-alphanumeric stripped) so manifest variants like
// "anti-hooking", "anti_hooking", and "antiHooking" all resolve. This mirrors
// the control mapping in docs/masvs-mapping.md; it is intentionally client-side
// data so it can track the doc without a server change.
var moduleMASVS = map[string][]string{
	"integrity":      {"CODE", "RESILIENCE"},
	"appintegrity":   {"CODE", "RESILIENCE"},
	"rasp":           {"PLATFORM", "RESILIENCE"},
	"attestation":    {"AUTH", "NETWORK"},
	"apiattestation": {"AUTH", "NETWORK"},
	"network":        {"NETWORK"},
	"tls":            {"NETWORK"},
	"obfuscation":    {"CODE", "RESILIENCE"},
	"antihooking":    {"RESILIENCE"},
	"hooking":        {"RESILIENCE"},
	"environment":    {"PLATFORM", "RESILIENCE"},
	"root":           {"PLATFORM", "RESILIENCE"},
	"jailbreak":      {"PLATFORM", "RESILIENCE"},
	"storage":        {"STORAGE"},
	"crypto":         {"CRYPTO"},
	"privacy":        {"PRIVACY"},
}

// normalizeModule lower-cases a module name and strips any non-alphanumeric
// characters so manifest naming variants resolve to one mapping key.
func normalizeModule(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// buildManifestProvenance is the subset of a build manifest the MASVS report
// reads. Both `modules` and `modules_enabled` are accepted (build plugins and
// protection profiles use different keys); `transforms` is surfaced verbatim as
// supporting provenance.
type buildManifestProvenance struct {
	Modules        []string `json:"modules"`
	ModulesEnabled []string `json:"modules_enabled"`
	Transforms     []string `json:"transforms"`
}

// MASVSCategoryCoverage is one MASVS category's coverage in a build report.
type MASVSCategoryCoverage struct {
	Category string   `json:"category"`
	Covered  bool     `json:"covered"`
	Modules  []string `json:"modules"`
}

// MASVSReport is the build's MASVS evidence: the build-hash proof, the manifest
// module/transform provenance, and per-category coverage derived from the
// module set. Gaps and notes make the limits of the evidence explicit (no PII,
// fail-honest about what the registry RPCs do and do not expose).
type MASVSReport struct {
	BuildID         string                  `json:"build_id"`
	AppID           string                  `json:"app_id"`
	BuildHash       string                  `json:"build_hash"`
	VersionName     string                  `json:"version_name"`
	VersionCode     int64                   `json:"version_code"`
	Modules         []string                `json:"modules"`
	Transforms      []string                `json:"transforms"`
	Categories      []MASVSCategoryCoverage `json:"categories"`
	CoveredCount    int                     `json:"covered_count"`
	TotalCategories int                     `json:"total_categories"`
	Gaps            []string                `json:"gaps"`
	Notes           []string                `json:"notes"`
}

// buildMASVSReport derives a MASVS evidence report from a registered build,
// reading only the build-hash proof and manifest provenance the registry RPC
// exposes. A missing or unparseable manifest is not an error: the report still
// renders the build proof and records the absence as a note, so the command is
// always informative.
func buildMASVSReport(b *ksealv1.Build) MASVSReport {
	rep := MASVSReport{
		BuildID:         b.GetId(),
		AppID:           b.GetAppId(),
		BuildHash:       b.GetBuildHash(),
		VersionName:     b.GetVersionName(),
		VersionCode:     b.GetVersionCode(),
		TotalCategories: len(masvsCategories),
	}

	manifest := strings.TrimSpace(b.GetManifest())
	if manifest == "" {
		rep.Notes = append(rep.Notes, "build manifest is empty: no module provenance to map; only the build-hash proof is available")
	} else {
		var prov buildManifestProvenance
		if err := json.Unmarshal([]byte(manifest), &prov); err != nil {
			rep.Notes = append(rep.Notes, "build manifest is not valid JSON: module coverage could not be derived")
		} else {
			rep.Modules = dedupeSorted(append(append([]string(nil), prov.Modules...), prov.ModulesEnabled...))
			rep.Transforms = dedupeSorted(prov.Transforms)
		}
	}

	// Accumulate the contributing modules per MASVS category.
	byCategory := map[string]map[string]struct{}{}
	for _, cat := range masvsCategories {
		byCategory[cat] = map[string]struct{}{}
	}
	for _, m := range rep.Modules {
		cats, ok := moduleMASVS[normalizeModule(m)]
		if !ok {
			rep.Notes = append(rep.Notes, "module \""+m+"\" is not mapped to a MASVS category")
			continue
		}
		for _, cat := range cats {
			byCategory[cat][m] = struct{}{}
		}
	}

	for _, cat := range masvsCategories {
		mods := setToSorted(byCategory[cat])
		covered := len(mods) > 0
		rep.Categories = append(rep.Categories, MASVSCategoryCoverage{Category: cat, Covered: covered, Modules: mods})
		if covered {
			rep.CoveredCount++
		} else {
			rep.Gaps = append(rep.Gaps, cat)
		}
	}

	rep.Notes = append(rep.Notes,
		"evidence is derived from the registered build-manifest module set and the build-hash proof; the registry/query RPCs do not expose per-control MASTG verification status or signed attestation artifacts")
	return rep
}

func dedupeSorted(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func setToSorted(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
