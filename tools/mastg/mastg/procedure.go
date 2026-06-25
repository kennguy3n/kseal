package mastg

import (
	"regexp"
	"sort"
	"strings"
)

// Plane classifies where a verification procedure is exercised. It determines
// the default status when no evidence is supplied: device procedures are MASTG
// checks that must be run against a build, while everything else is verified by
// another method (server/build/etc.) and is surfaced informationally.
type Plane string

const (
	PlaneDevice Plane = "device" // a MASTG-* procedure run against the app/build
	PlaneServer Plane = "server" // verified by a server-side test
	PlaneOther  Plane = "other"  // verified by another named method (build/config/etc.)
)

// Procedure is a single MASTG verification procedure derived from one catalog
// control. It carries the catalog provenance plus the parsed MASTG test areas,
// the verification method label, and the concrete check text.
type Procedure struct {
	ID         string   `json:"id"`
	Category   string   `json:"category"`
	Objective  string   `json:"objective"`
	Control    string   `json:"control"`
	MASTGTests []string `json:"mastg_tests"`
	Method     string   `json:"method"`
	Plane      Plane    `json:"plane"`
	Steps      string   `json:"steps"`
	Raw        string   `json:"raw"`
}

var mastgTokenRE = regexp.MustCompile(`MASTG-[A-Z]+`)

// Procedures flattens the catalog into the ordered list of MASTG verification
// procedures, one per control, in doc order.
func (c *Catalog) Procedures() []Procedure {
	var out []Procedure
	for _, cat := range c.Categories {
		for _, ctrl := range cat.Controls {
			out = append(out, deriveProcedure(cat.Name, ctrl))
		}
	}
	return out
}

func deriveProcedure(category string, ctrl Control) Procedure {
	tests := dedupeSorted(mastgTokenRE.FindAllString(ctrl.MASTG, -1))
	method, steps := splitMethod(ctrl.MASTG, tests)
	return Procedure{
		ID:         category + "/" + slug(ctrl.Objective),
		Category:   category,
		Objective:  ctrl.Objective,
		Control:    ctrl.Control,
		MASTGTests: tests,
		Method:     method,
		Plane:      classifyPlane(method, tests),
		Steps:      steps,
		Raw:        ctrl.MASTG,
	}
}

// splitMethod parses the verification-method label and the concrete steps from
// a MASTG-column cell. The cell is "<method>: <steps>"; for MASTG rows the
// method is the comma-joined MASTG test areas (the prefix before ":" is itself
// the token list). The label is taken verbatim from the doc, so new methods
// flow through without code changes.
func splitMethod(cell string, tests []string) (method, steps string) {
	steps = cell
	prefix := ""
	if i := strings.Index(cell, ": "); i >= 0 {
		prefix = strings.TrimSpace(cell[:i])
		steps = strings.TrimSpace(cell[i+2:])
	}
	if len(tests) > 0 {
		return strings.Join(tests, ", "), steps
	}
	if prefix != "" {
		return prefix, steps
	}
	return "Other", steps
}

// classifyPlane maps a procedure to its plane from the parsed method label.
// MASTG-tagged rows are device procedures; a "Server ..." method is server;
// anything else is verified by another named method.
func classifyPlane(method string, tests []string) Plane {
	if len(tests) > 0 {
		return PlaneDevice
	}
	if strings.HasPrefix(strings.ToLower(method), "server") {
		return PlaneServer
	}
	return PlaneOther
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = nonSlug.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

func dedupeSorted(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	for _, x := range xs {
		set[x] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for x := range set {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}
