// Package datasafety generates Google Play Console Data-Safety form answers for
// the kseal SDK from the canonical data contract. It produces both a
// machine-readable form (stable JSON the integrator can diff in CI or feed to
// the Play Console bulk-upload CSV path) and a human-readable Markdown summary
// that mirrors the questions the Play Console asks.
package datasafety

import (
	"sort"
	"strings"

	"github.com/kennguy3n/kseal/tools/privacy-manifest/contract"
)

// Options tunes generation.
type Options struct {
	// IncludeOptional includes data types that are off by default in the
	// contract (e.g. coarse region). A host app that enables those features
	// must disclose them.
	IncludeOptional bool
}

// DataTypeAnswer is one row of the Data-Safety form: a data type the app
// collects, with the per-type answers the Play Console requires.
type DataTypeAnswer struct {
	Category             string   `json:"category"`
	DataType             string   `json:"data_type"`
	Collected            bool     `json:"collected"`
	Shared               bool     `json:"shared"`
	ProcessedEphemerally bool     `json:"processed_ephemerally"`
	Optional             bool     `json:"optional"`
	Purposes             []string `json:"purposes"`
	SourceItem           string   `json:"source_item"`
	Description          string   `json:"description"`
}

// Form is the full Data-Safety declaration.
type Form struct {
	SDK                          string           `json:"sdk"`
	CollectsData                 bool             `json:"collects_data"`
	SharesData                   bool             `json:"shares_data"`
	EncryptedInTransit           bool             `json:"encrypted_in_transit"`
	DataDeletionRequestSupported bool             `json:"data_deletion_request_supported"`
	DataDeletionNote             string           `json:"data_deletion_note,omitempty"`
	DataTypes                    []DataTypeAnswer `json:"data_types"`
	NotCollected                 []string         `json:"not_collected"`
}

// Generate builds the Data-Safety form from the data contract.
//
// The Play Console lists each data type once, so contract items that project
// onto the same Android (category, data_type) are merged — mirroring the iOS
// generator: purposes union, "optional" demotes (the type is mandatory if any
// contributing item is mandatory), "shared" promotes (shared if any item is
// shared), and source ids/descriptions are unioned. "Optional" maps to the
// contract's Optional flag (the Play Console asks whether the user can use the
// app without providing the data). Rows are sorted by (category, data_type) for
// deterministic output.
func Generate(c *contract.Contract, opts Options) *Form {
	type agg struct {
		shared      bool
		optional    bool
		purposes    map[string]struct{}
		source      []string
		description map[string]struct{}
	}
	byType := map[string]*agg{}
	order := []string{}

	for _, it := range c.PersonalDataItems() {
		if it.Android == nil {
			continue
		}
		if it.Optional && !it.DefaultCollected && !opts.IncludeOptional {
			continue
		}
		key := it.Android.Category + "\x00" + it.Android.DataType
		a := byType[key]
		if a == nil {
			// optional starts true so the &&-merge leaves a type optional only
			// when every contributing item is optional.
			a = &agg{optional: true, purposes: map[string]struct{}{}, description: map[string]struct{}{}}
			byType[key] = a
			order = append(order, key)
		}
		a.shared = a.shared || c.DataSharing.SharedWithThirdParties
		a.optional = a.optional && it.Optional
		a.source = append(a.source, it.ID)
		for _, p := range it.Android.Purposes {
			a.purposes[p] = struct{}{}
		}
		if it.Description != "" {
			a.description[it.Description] = struct{}{}
		}
	}

	rows := make([]DataTypeAnswer, 0, len(order))
	for _, key := range order {
		a := byType[key]
		cat, dataType, _ := strings.Cut(key, "\x00")
		sort.Strings(a.source)
		rows = append(rows, DataTypeAnswer{
			Category:  cat,
			DataType:  dataType,
			Collected: true,
			Shared:    a.shared,
			// kseal persists at least aggregates (raw is opt-in), so collected
			// data is not processed only ephemerally.
			ProcessedEphemerally: false,
			Optional:             a.optional,
			Purposes:             keysSorted(a.purposes),
			SourceItem:           strings.Join(a.source, ","),
			Description:          strings.Join(keysSorted(a.description), "; "),
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Category != rows[j].Category {
			return rows[i].Category < rows[j].Category
		}
		return rows[i].DataType < rows[j].DataType
	})

	notCollected := append([]string(nil), c.NotCollected...)
	sort.Strings(notCollected)

	return &Form{
		SDK:                          c.SDK,
		CollectsData:                 len(rows) > 0,
		SharesData:                   c.DataSharing.SharedWithThirdParties,
		EncryptedInTransit:           c.Transport.EncryptedInTransit,
		DataDeletionRequestSupported: c.StoreDisclosure.DataDeletionRequestSupported,
		DataDeletionNote:             c.StoreDisclosure.DataDeletionNote,
		DataTypes:                    rows,
		NotCollected:                 notCollected,
	}
}

func keysSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
