package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// outputFormat is the rendering mode for command results.
type outputFormat string

const (
	outputTable outputFormat = "table"
	outputJSON  outputFormat = "json"
)

func parseOutputFormat(s string) (outputFormat, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(outputTable):
		return outputTable, nil
	case string(outputJSON):
		return outputJSON, nil
	default:
		return "", fmt.Errorf("invalid --output %q: want json or table", s)
	}
}

// table is a simple column-oriented rendering used for human output.
type table struct {
	Headers []string
	Rows    [][]string
}

func (t table) render(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if len(t.Headers) > 0 {
		if _, err := fmt.Fprintln(tw, strings.Join(t.Headers, "\t")); err != nil {
			return err
		}
	}
	for _, row := range t.Rows {
		if _, err := fmt.Fprintln(tw, strings.Join(row, "\t")); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// renderJSON writes v as indented JSON with a trailing newline. Output is
// deterministic (sorted keys via struct field order / map marshaling) so it is
// safe for golden-file assertions and downstream `jq` parsing.
func renderJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// listEnvelope is the JSON shape for list responses: a named item slice plus an
// optional pagination token. The items key varies per resource so scripts can
// `jq '.tenants[]'` etc.
type listEnvelope struct {
	items         any
	itemsKey      string
	nextPageToken string
}

func (l listEnvelope) MarshalJSON() ([]byte, error) {
	m := map[string]any{l.itemsKey: l.items}
	if l.nextPageToken != "" {
		m["next_page_token"] = l.nextPageToken
	}
	return json.Marshal(m)
}

// listJSON builds a list envelope for `--output json`.
func listJSON(itemsKey string, items any, nextPageToken string) listEnvelope {
	return listEnvelope{items: items, itemsKey: itemsKey, nextPageToken: nextPageToken}
}

// emit renders a result in the active output format. The JSON shape is taken
// from jsonValue; the table is rendered from tbl. Keeping the two explicit (vs.
// reflecting over one structure) lets table output stay compact and ordered
// while JSON stays machine-stable.
func (c *CLI) emit(jsonValue any, tbl table) error {
	switch c.output {
	case outputJSON:
		return renderJSON(c.out, jsonValue)
	default:
		return tbl.render(c.out)
	}
}
