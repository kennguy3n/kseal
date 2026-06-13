// Package datasafety generates Google Play Console Data-Safety form answers for
// the kseal SDK from the canonical data contract. It produces both a
// machine-readable form (stable JSON the integrator can diff in CI or feed to
// the Play Console bulk-upload CSV path) and a human-readable Markdown summary
// that mirrors the questions the Play Console asks.
package datasafety

import (
	"sort"

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
// Each Android-mapped personal-data item becomes one form row. "Optional" maps
// to the contract's Optional flag (the Play Console asks whether the user can
// use the app without providing the data); "Shared" is the contract's
// third-party-sharing posture (the same for every type). Rows are sorted by
// (category, data_type) for deterministic output.
func Generate(c *contract.Contract, opts Options) *Form {
	rows := make([]DataTypeAnswer, 0, len(c.Collected))
	for _, it := range c.PersonalDataItems() {
		if it.Android == nil {
			continue
		}
		if it.Optional && !it.DefaultCollected && !opts.IncludeOptional {
			continue
		}
		purposes := append([]string(nil), it.Android.Purposes...)
		sort.Strings(purposes)
		rows = append(rows, DataTypeAnswer{
			Category:  it.Android.Category,
			DataType:  it.Android.DataType,
			Collected: true,
			Shared:    c.DataSharing.SharedWithThirdParties,
			// kseal persists at least aggregates (raw is opt-in), so collected
			// data is not processed only ephemerally.
			ProcessedEphemerally: false,
			Optional:             it.Optional,
			Purposes:             purposes,
			SourceItem:           it.ID,
			Description:          it.Description,
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
