package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	yaml "gopkg.in/yaml.v3"
)

// outputFormat is the rendering mode for command results.
type outputFormat string

const (
	outputTable outputFormat = "table"
	outputJSON  outputFormat = "json"
	outputYAML  outputFormat = "yaml"
)

// outputFormats lists the supported --output values in a stable order. It is
// reused for help text and shell-completion candidates so they never drift.
var outputFormats = []string{string(outputTable), string(outputJSON), string(outputYAML)}

func parseOutputFormat(s string) (outputFormat, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(outputTable):
		return outputTable, nil
	case string(outputJSON):
		return outputJSON, nil
	case string(outputYAML), "yml":
		return outputYAML, nil
	default:
		return "", fmt.Errorf("invalid --output %q: want one of %s", s, strings.Join(outputFormats, "|"))
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

// renderJSONCompact writes v as a single line of JSON followed by a newline
// (newline-delimited JSON / NDJSON). It is used for streaming output
// (`events tail`) so each event is one self-contained line that `jq -c`,
// `while read`, and log shippers can consume incrementally without buffering a
// whole document.
func renderJSONCompact(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// renderYAML writes v as block-style YAML. To keep the YAML field order and
// naming identical to --output json (the documented, golden-tested shape), v is
// first marshaled to JSON and then re-encoded as YAML: JSON is a strict subset
// of YAML, so the round-trip preserves the struct field order rather than the
// alphabetical order a direct yaml.Marshal of a Go map would emit. Output is
// deterministic and safe for `yq` parsing and golden-file assertions.
func renderYAML(w io.Writer, v any) error {
	node, err := yamlNode(v)
	if err != nil {
		return err
	}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(node); err != nil {
		return err
	}
	return enc.Close()
}

// renderYAMLCompact writes v as a single YAML document terminated by the
// document separator ("---"). It is the streaming analogue of renderJSONCompact
// for `events tail`, so each event is a self-contained YAML document that
// `yq -s` and document-aware consumers can read incrementally.
func renderYAMLCompact(w io.Writer, v any) error {
	if err := renderYAML(w, v); err != nil {
		return err
	}
	_, err := io.WriteString(w, "---\n")
	return err
}

// yamlNode converts an arbitrary value into a yaml.Node via its JSON encoding so
// the YAML mirrors the JSON projection exactly (field names from json tags,
// declaration order preserved).
func yamlNode(v any) (*yaml.Node, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	var node yaml.Node
	if err := yaml.Unmarshal(buf.Bytes(), &node); err != nil {
		return nil, err
	}
	// JSON parses as YAML flow style; clear the style so the encoder emits
	// readable block YAML and quotes scalars only where required.
	forceBlockStyle(&node)
	return &node, nil
}

// forceBlockStyle recursively resets the flow/quoting style inherited from the
// JSON parse so the YAML encoder renders block mappings and sequences.
func forceBlockStyle(n *yaml.Node) {
	n.Style = 0
	for _, child := range n.Content {
		forceBlockStyle(child)
	}
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

// structured reports whether the active output format is a machine-readable
// document format (json or yaml) rather than the human table. Commands that
// special-case rendering (capability fallbacks, streaming tails) branch on this
// so json and yaml stay in lockstep.
func (c *CLI) structured() bool {
	return c.output == outputJSON || c.output == outputYAML
}

// renderStructured writes v in the active machine-readable format. It must only
// be called when c.structured() is true.
func (c *CLI) renderStructured(v any) error {
	if c.output == outputYAML {
		return renderYAML(c.out, v)
	}
	return renderJSON(c.out, v)
}

// emit renders a result in the active output format. The structured shape is
// taken from jsonValue (used for both json and yaml); the table is rendered
// from tbl. Keeping the two explicit (vs. reflecting over one structure) lets
// table output stay compact and ordered while the machine formats stay stable.
func (c *CLI) emit(jsonValue any, tbl table) error {
	if c.structured() {
		return c.renderStructured(jsonValue)
	}
	return tbl.render(c.out)
}
