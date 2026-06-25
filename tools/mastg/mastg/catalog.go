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
	cols := unsetTableColumns()

	for sc.Scan() {
		trimmed := strings.TrimSpace(sc.Text())

		if name, ok := categoryHeading(trimmed); ok {
			cat.Categories = append(cat.Categories, Category{Name: name})
			curIdx = len(cat.Categories) - 1
			expectObjective, inObjective = true, false
			cols = unsetTableColumns()
			continue
		}
		if strings.HasPrefix(trimmed, "## ") {
			curIdx, expectObjective, inObjective = -1, false, false
			cols = unsetTableColumns()
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
			if isSeparator(cells) {
				continue
			}
			if parsed, ok := parseHeader(cells); ok {
				cols = parsed
				continue
			}
			if !cols.valid() {
				return nil, fmt.Errorf("category %q: control table missing required header before row %q", cur.Name, trimmed)
			}
			if len(cells) <= cols.max() {
				return nil, fmt.Errorf("category %q: malformed control row %q (want columns %v, got %d)", cur.Name, trimmed, cols.names(), len(cells))
			}
			cur.Controls = append(cur.Controls, Control{
				Objective: cells[cols.objective],
				Control:   cells[cols.control],
				Module:    cells[cols.module],
				MASTG:     cells[cols.mastg],
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

func isSeparator(cells []string) bool {
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

type tableColumns struct {
	objective int
	control   int
	module    int
	mastg     int
}

func unsetTableColumns() tableColumns {
	return tableColumns{objective: -1, control: -1, module: -1, mastg: -1}
}

func (c tableColumns) valid() bool {
	return c.objective >= 0 && c.control >= 0 && c.module >= 0 && c.mastg >= 0
}

func (c tableColumns) max() int {
	max := c.objective
	for _, v := range []int{c.control, c.module, c.mastg} {
		if v > max {
			max = v
		}
	}
	return max
}

func (c tableColumns) names() []string {
	return []string{"MASVS objective", "kseal control", "Module / component", "MASTG verification"}
}

func parseHeader(cells []string) (tableColumns, bool) {
	cols := unsetTableColumns()
	for i, cell := range cells {
		switch normalizedHeader(cell) {
		case "masvs objective":
			cols.objective = i
		case "kseal control":
			cols.control = i
		case "module component":
			cols.module = i
		case "mastg verification":
			cols.mastg = i
		}
	}
	return cols, cols.valid()
}

func normalizedHeader(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "/", " ")
	return strings.Join(strings.Fields(s), " ")
}
