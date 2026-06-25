// Package catalog parses docs/masvs-mapping.md — the authoritative kseal MASVS
// control catalog — into structured categories and controls.
//
// The report is generated against this catalog rather than a hard-coded table,
// so editing the Markdown (adding, removing, or altering a control) is reflected
// in every subsequent report without code changes.
package catalog

import (
	"bufio"
	"fmt"
	"strings"
)

// Catalog is the ordered set of MASVS categories parsed from the mapping doc.
type Catalog struct {
	Categories []Category
}

// Category is one MASVS-* section with its objective and controls, in doc order.
type Category struct {
	Name      string // e.g. "MASVS-RESILIENCE"
	Objective string
	Controls  []Control
}

// Control is one row of a category table.
type Control struct {
	Objective string // first column ("MASVS objective")
	Control   string // "kseal control"
	Module    string // "Module / component"
	MASTG     string // "MASTG verification"
}

// Find returns the category by exact name.
func (c *Catalog) Find(name string) (*Category, bool) {
	for i := range c.Categories {
		if c.Categories[i].Name == name {
			return &c.Categories[i], true
		}
	}
	return nil, false
}

// Parse reads a masvs-mapping.md document. Only sections whose heading begins
// with "MASVS-" are treated as control categories (the coverage summary table
// and prose are ignored).
func Parse(markdown string) (*Catalog, error) {
	cat := &Catalog{}
	scanner := bufio.NewScanner(strings.NewReader(markdown))
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	var current *Category
	expectObjective := false
	inObjective := false

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t")
		trimmed := strings.TrimSpace(line)

		if name, ok := categoryHeading(trimmed); ok {
			cat.Categories = append(cat.Categories, Category{Name: name})
			current = &cat.Categories[len(cat.Categories)-1]
			expectObjective = true
			inObjective = false
			continue
		}
		// A new non-category heading ends the current category's table region.
		if strings.HasPrefix(trimmed, "## ") {
			current = nil
			expectObjective = false
			inObjective = false
			continue
		}
		if current == nil {
			continue
		}
		if expectObjective && strings.HasPrefix(trimmed, "Objective:") {
			current.Objective = strings.TrimSpace(strings.TrimPrefix(trimmed, "Objective:"))
			expectObjective = false
			inObjective = true
			continue
		}
		// The objective sentence may wrap across lines; accumulate until a blank
		// line, table, or heading ends it.
		if inObjective {
			if trimmed == "" || strings.HasPrefix(trimmed, "|") || strings.HasPrefix(trimmed, "#") {
				inObjective = false
			} else {
				current.Objective = strings.TrimSpace(current.Objective + " " + trimmed)
				continue
			}
		}
		if cells, ok := tableRow(trimmed); ok {
			if isHeaderOrSeparator(cells) {
				continue
			}
			if len(cells) < 4 {
				return nil, fmt.Errorf("category %q: malformed control row %q (want 4 columns, got %d)", current.Name, trimmed, len(cells))
			}
			current.Controls = append(current.Controls, Control{
				Objective: cells[0],
				Control:   cells[1],
				Module:    cells[2],
				MASTG:     cells[3],
			})
		}
	}
	if err := scanner.Err(); err != nil {
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
