package xcprivacy

import (
	"strings"
)

// A tiny, deterministic Apple plist (XML) encoder. Apple's PrivacyInfo.xcprivacy
// is an ordered property list; encoding/xml cannot preserve the key/value
// ordering plists require, so we render the handful of node types a privacy
// manifest uses directly. Output matches `plutil`'s conventions (tab indent,
// <true/>/<false/>, <array/> for empty collections) so it round-trips through
// Xcode and is stable for golden-file assertions.
type pval interface {
	write(b *strings.Builder, indent int)
}

type pbool bool

func (v pbool) write(b *strings.Builder, _ int) {
	if v {
		b.WriteString("<true/>")
		return
	}
	b.WriteString("<false/>")
}

type pstring string

func (v pstring) write(b *strings.Builder, _ int) {
	b.WriteString("<string>")
	b.WriteString(escapeXML(string(v)))
	b.WriteString("</string>")
}

type parray []pval

func (v parray) write(b *strings.Builder, indent int) {
	if len(v) == 0 {
		b.WriteString("<array/>")
		return
	}
	b.WriteString("<array>\n")
	for _, item := range v {
		writeIndent(b, indent+1)
		item.write(b, indent+1)
		b.WriteByte('\n')
	}
	writeIndent(b, indent)
	b.WriteString("</array>")
}

// pdict is an ordered dictionary: keys and vals are index-aligned so emission
// order is exactly authoring order (plists are order-significant).
type pdict struct {
	keys []string
	vals []pval
}

func (d *pdict) set(key string, val pval) *pdict {
	d.keys = append(d.keys, key)
	d.vals = append(d.vals, val)
	return d
}

func (d *pdict) write(b *strings.Builder, indent int) {
	if len(d.keys) == 0 {
		b.WriteString("<dict/>")
		return
	}
	b.WriteString("<dict>\n")
	for i, k := range d.keys {
		writeIndent(b, indent+1)
		b.WriteString("<key>")
		b.WriteString(escapeXML(k))
		b.WriteString("</key>\n")
		writeIndent(b, indent+1)
		d.vals[i].write(b, indent+1)
		b.WriteByte('\n')
	}
	writeIndent(b, indent)
	b.WriteString("</dict>")
}

func writeIndent(b *strings.Builder, n int) {
	for i := 0; i < n; i++ {
		b.WriteByte('\t')
	}
}

func escapeXML(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
	)
	return r.Replace(s)
}

// renderPlist wraps a root value in the standard plist document header.
func renderPlist(root pval) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n")
	root.write(&b, 0)
	b.WriteString("\n</plist>\n")
	return []byte(b.String())
}

// strs builds a plist <array> of <string> from a Go slice.
func strs(xs []string) parray {
	out := make(parray, 0, len(xs))
	for _, x := range xs {
		out = append(out, pstring(x))
	}
	return out
}
