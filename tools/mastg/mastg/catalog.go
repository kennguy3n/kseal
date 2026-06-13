// Package mastg maps the kseal MASVS control catalog (docs/masvs-mapping.md) to
// OWASP MASTG verification procedures and runs them against per-release
// evidence, emitting a pass/observed report. It complements tools/masvs-report
// (which overlays build-proof evidence onto the catalog) by focusing on the
// MASTG verification *procedures* and their run status for a release.
package mastg

import (
	"bufio"
	"fmt"
	"strings"
)

// Catalog is the ordered set of MASVS categories parsed from the mapping doc.
type Catalog struct {
	Categories []Category
}

// Category is one MASVS-* section with its controls, in doc order.
type Category struct {
	Name      string
	Objective string
	Controls  []Control
}

// Control is one row of a category table in the mapping doc.
type Control struct {
	Objective string
	Control   string
	Phase     string
	Module    string
	MASTG     string
}

// ParseCatalog reads docs/masvs-mapping.md. Only "## MASVS-*" sections are
// treated as control categories; the coverage summary and prose are ignored.
// Parsing the doc (rather than hard-coding a table) means edits to the mapping
// flow through to the MASTG report with no code change.
func ParseCatalog(markdown string) (*Catalog, error) {
	cat := &Catalog{}
	sc := bufio.NewScanner(strings.NewReader(markdown))
	sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	// Track the open category by index rather than a *Category into the slice:
	// appends to cat.Categories can reallocate the backing array, which would
	// dangle a held pointer. -1 means "no open category".
	curIdx := -1
	expectObjective, inObjective := false, false

	for sc.Scan() {
		trimmed := strings.TrimSpace(sc.Text())

		if name, ok := categoryHeading(trimmed); ok {
			cat.Categories = append(cat.Categories, Category{Name: name})
			curIdx = len(cat.Categories) - 1
			expectObjective, inObjective = true, false
			continue
		}
		if strings.HasPrefix(trimmed, "## ") {
			curIdx, expectObjective, inObjective = -1, false, false
			continue
		}
		if curIdx < 0 {
			continue
		}
		cur := &cat.Categories[curIdx]
		if expectObjective && strings.HasPrefix(trimmed, "Objective:") {
			cur.Objective = strings.TrimSpace(strings.TrimPrefix(trimmed, "Objective:"))
			expectObjective, inObjective = false, true
			continue
		}
		if inObjective {
			if trimmed == "" || strings.HasPrefix(trimmed, "|") || strings.HasPrefix(trimmed, "#") {
				inObjective = false
			} else {
				cur.Objective = strings.TrimSpace(cur.Objective + " " + trimmed)
				continue
			}
		}
		if cells, ok := tableRow(trimmed); ok {
			if isHeaderOrSeparator(cells) {
				continue
			}
			if len(cells) < 5 {
				return nil, fmt.Errorf("category %q: malformed control row %q (want 5 columns, got %d)", cur.Name, trimmed, len(cells))
			}
			cur.Controls = append(cur.Controls, Control{
				Objective: cells[0], Control: cells[1], Phase: cells[2], Module: cells[3], MASTG: cells[4],
			})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read mapping doc: %w", err)
	}
	if len(cat.Categories) == 0 {
		return nil, fmt.Errorf("no MASVS-* categories found in mapping doc")
	}
	return cat, nil
}

func categoryHeading(line string) (string, bool) {
	if !strings.HasPrefix(line, "## ") {
		return "", false
	}
	name := strings.TrimSpace(strings.TrimPrefix(line, "## "))
	if strings.HasPrefix(name, "MASVS-") {
		return name, true
	}
	return "", false
}

func tableRow(line string) ([]string, bool) {
	if !strings.HasPrefix(line, "|") {
		return nil, false
	}
	parts := strings.Split(strings.Trim(line, "|"), "|")
	cells := make([]string, len(parts))
	for i, p := range parts {
		cells[i] = strings.TrimSpace(p)
	}
	return cells, true
}

func isHeaderOrSeparator(cells []string) bool {
	if len(cells) > 0 && strings.EqualFold(cells[0], "MASVS objective") {
		return true
	}
	for _, c := range cells {
		if c == "" {
			continue
		}
		if strings.Trim(c, "-: ") != "" {
			return false
		}
	}
	return true
}
