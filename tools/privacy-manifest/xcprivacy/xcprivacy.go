// Package xcprivacy generates an Apple PrivacyInfo.xcprivacy manifest for the
// kseal SDK from the canonical data contract. The manifest declares the SDK's
// data collection (NSPrivacyCollectedDataTypes), tracking posture
// (NSPrivacyTracking), and the required-reason APIs the SDK invokes
// (NSPrivacyAccessedAPITypes). Output is deterministic so it can be committed
// to a host app and asserted in golden tests.
package xcprivacy

import (
	"sort"

	"github.com/kennguy3n/kseal/tools/privacy-manifest/contract"
)

// Options tunes generation.
type Options struct {
	// IncludeOptional includes data types that are off by default in the
	// contract (e.g. coarse region). A host app that enables those features
	// must declare them, so this is opt-in.
	IncludeOptional bool
}

// CollectedType is one NSPrivacyCollectedDataTypes entry.
type CollectedType struct {
	Type       string   `json:"type"`
	Linked     bool     `json:"linked"`
	Tracking   bool     `json:"tracking"`
	Purposes   []string `json:"purposes"`
	SourceItem string   `json:"source_item"`
	Optional   bool     `json:"optional"`
}

// AccessedAPI is one NSPrivacyAccessedAPITypes entry.
type AccessedAPI struct {
	Type    string   `json:"type"`
	Reasons []string `json:"reasons"`
}

// Manifest is the structured privacy manifest: it renders to either the Apple
// plist (XML) or a JSON summary, both from the same data.
type Manifest struct {
	Tracking        bool            `json:"tracking"`
	TrackingDomains []string        `json:"tracking_domains"`
	CollectedTypes  []CollectedType `json:"collected_data_types"`
	AccessedAPIs    []AccessedAPI   `json:"accessed_api_types"`
}

// Generate builds a Manifest from the data contract.
//
// Apple lists each NSPrivacyCollectedDataType once with the union of its
// purposes, so contract items that map to the same Apple type are merged. The
// merge is deterministic (sorted types, deduped+sorted purposes).
func Generate(c *contract.Contract, opts Options) *Manifest {
	type agg struct {
		linked   bool
		tracking bool
		purposes map[string]struct{}
		source   []string
		optional bool
	}
	byType := map[string]*agg{}
	order := []string{}

	for _, it := range c.PersonalDataItems() {
		if it.IOS == nil {
			continue
		}
		if it.Optional && !it.DefaultCollected && !opts.IncludeOptional {
			continue
		}
		a := byType[it.IOS.CollectedDataType]
		if a == nil {
			a = &agg{purposes: map[string]struct{}{}}
			byType[it.IOS.CollectedDataType] = a
			order = append(order, it.IOS.CollectedDataType)
		}
		// Fail safe: any contributing item that is linked or used for tracking
		// promotes the whole Apple type, since the declaration is per-type.
		a.linked = a.linked || it.LinkedToIdentity
		a.tracking = a.tracking || it.UsedForTracking
		a.optional = a.optional || it.Optional
		a.source = append(a.source, it.ID)
		for _, p := range it.IOS.Purposes {
			a.purposes[p] = struct{}{}
		}
	}

	sort.Strings(order)
	collected := make([]CollectedType, 0, len(order))
	for _, typ := range order {
		a := byType[typ]
		purposes := keysSorted(a.purposes)
		sort.Strings(a.source)
		collected = append(collected, CollectedType{
			Type:       typ,
			Linked:     a.linked,
			Tracking:   a.tracking,
			Purposes:   purposes,
			SourceItem: joinSorted(a.source),
			Optional:   a.optional,
		})
	}

	apis := make([]AccessedAPI, 0, len(c.IOSReasonAPIs))
	for _, r := range c.IOSReasonAPIs {
		reasons := append([]string(nil), r.Reasons...)
		sort.Strings(reasons)
		apis = append(apis, AccessedAPI{Type: r.APICategory, Reasons: reasons})
	}
	sort.Slice(apis, func(i, j int) bool { return apis[i].Type < apis[j].Type })

	return &Manifest{
		// kseal never tracks (no cross-app/site linkage); the contract's
		// sharing posture is authoritative and asserted in tests.
		Tracking:        c.DataSharing.UsedForTracking,
		TrackingDomains: []string{},
		CollectedTypes:  collected,
		AccessedAPIs:    apis,
	}
}

// XML renders the Apple PrivacyInfo.xcprivacy property list.
func (m *Manifest) XML() []byte {
	root := &pdict{}
	root.set("NSPrivacyTracking", pbool(m.Tracking))
	root.set("NSPrivacyTrackingDomains", strs(m.TrackingDomains))

	collected := make(parray, 0, len(m.CollectedTypes))
	for _, ct := range m.CollectedTypes {
		d := &pdict{}
		d.set("NSPrivacyCollectedDataType", pstring(ct.Type))
		d.set("NSPrivacyCollectedDataTypeLinked", pbool(ct.Linked))
		d.set("NSPrivacyCollectedDataTypeTracking", pbool(ct.Tracking))
		d.set("NSPrivacyCollectedDataTypePurposes", strs(ct.Purposes))
		collected = append(collected, d)
	}
	root.set("NSPrivacyCollectedDataTypes", collected)

	apis := make(parray, 0, len(m.AccessedAPIs))
	for _, api := range m.AccessedAPIs {
		d := &pdict{}
		d.set("NSPrivacyAccessedAPIType", pstring(api.Type))
		d.set("NSPrivacyAccessedAPITypeReasons", strs(api.Reasons))
		apis = append(apis, d)
	}
	root.set("NSPrivacyAccessedAPITypes", apis)

	return renderPlist(root)
}

func keysSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func joinSorted(xs []string) string {
	switch len(xs) {
	case 0:
		return ""
	case 1:
		return xs[0]
	}
	out := xs[0]
	for _, x := range xs[1:] {
		out += "," + x
	}
	return out
}
