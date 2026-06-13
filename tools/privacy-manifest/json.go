package main

import (
	"bytes"
	"encoding/json"

	"github.com/kennguy3n/kseal/tools/privacy-manifest/xcprivacy"
)

// jsonSummary renders the manifest as a deterministic, indented JSON document
// (machine-readable mode). The plist is the artifact Xcode consumes; this
// summary is for review and CI diffing.
func jsonSummary(m *xcprivacy.Manifest) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
