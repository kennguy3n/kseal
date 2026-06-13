package datasafety

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// JSON renders the form as deterministic, indented JSON (machine-readable mode).
func (f *Form) JSON() ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// Markdown renders a human-readable summary mirroring the Play Console
// Data-Safety questionnaire: the top-level data-collection/security answers, a
// per-data-type table, and the explicit not-collected list.
func (f *Form) Markdown() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Google Play Data Safety — %s\n\n", f.SDK)
	b.WriteString("Generated from the kseal SDK data contract. These answers cover the data the\n")
	b.WriteString("kseal SDK contributes; combine them with your app's own data collection before\n")
	b.WriteString("submitting the Play Console form.\n\n")

	b.WriteString("## Data collection and security\n\n")
	fmt.Fprintf(&b, "- Does the app collect or share user data? **%s**\n", yesNo(f.CollectsData))
	fmt.Fprintf(&b, "- Is all collected user data encrypted in transit? **%s**\n", yesNo(f.EncryptedInTransit))
	fmt.Fprintf(&b, "- Is any data shared with third parties? **%s**\n", yesNo(f.SharesData))
	fmt.Fprintf(&b, "- Can users request that their data be deleted? **%s**\n", yesNo(f.DataDeletionRequestSupported))
	if f.DataDeletionNote != "" {
		fmt.Fprintf(&b, "  - %s\n", f.DataDeletionNote)
	}
	b.WriteString("\n")

	b.WriteString("## Data types collected\n\n")
	if len(f.DataTypes) == 0 {
		b.WriteString("_No user data types are collected by default._\n\n")
	} else {
		b.WriteString("| Category | Data type | Collected | Shared | Optional | Purposes |\n")
		b.WriteString("|---|---|---|---|---|---|\n")
		for _, d := range f.DataTypes {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
				d.Category, d.DataType, yesNo(d.Collected), yesNo(d.Shared), yesNo(d.Optional),
				strings.Join(d.Purposes, "; "))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Explicitly not collected\n\n")
	for _, n := range f.NotCollected {
		fmt.Fprintf(&b, "- %s\n", n)
	}
	return []byte(b.String())
}
