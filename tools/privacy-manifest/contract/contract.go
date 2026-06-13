// Package contract is the canonical, machine-readable kseal SDK data contract:
// a declarative spec of exactly what the SDK collects and transmits. It is the
// single source of truth shared by the store-disclosure generators (the iOS
// privacy-manifest generator in this module and the Google Data-Safety helper),
// so both artifacts fall out of one description that is pinned to the wire
// schema in proto/kseal/v1/telemetry.proto.
//
// The contract is embedded so consumers work regardless of working directory; a
// caller may also Load an alternative file (e.g. a tenant-customized contract).
package contract

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// canonicalJSON is the checked-in kseal data contract, embedded so the
// generators and CLI never depend on the working directory.
//
//go:embed kseal-data-contract.json
var canonicalJSON []byte

// Contract is the top-level data contract document.
type Contract struct {
	Schema          string          `json:"schema"`
	SDK             string          `json:"sdk"`
	SDKDisplayName  string          `json:"sdk_display_name"`
	Description     string          `json:"description"`
	SourceOfTruth   map[string]any  `json:"source_of_truth,omitempty"`
	Transport       Transport       `json:"transport"`
	DataSharing     DataSharing     `json:"data_sharing"`
	StoreDisclosure StoreDisclosure `json:"store_disclosure"`
	Retention       map[string]any  `json:"retention,omitempty"`
	Collected       []DataItem      `json:"collected"`
	NotCollected    []string        `json:"not_collected"`
	IOSReasonAPIs   []ReasonAPI     `json:"ios_required_reason_apis"`
}

// Transport describes how telemetry leaves the device.
type Transport struct {
	EncryptedInTransit bool   `json:"encrypted_in_transit"`
	Protocol           string `json:"protocol"`
	Payload            string `json:"payload"`
}

// DataSharing describes third-party sharing posture.
type DataSharing struct {
	SharedWithThirdParties bool   `json:"shared_with_third_parties"`
	Sold                   bool   `json:"sold"`
	UsedForTracking        bool   `json:"used_for_tracking"`
	Note                   string `json:"note"`
}

// StoreDisclosure carries store-form answers that are not per-data-type, such
// as whether users can request deletion. It keeps the Data-Safety helper fully
// data-driven instead of hardcoding policy answers.
type StoreDisclosure struct {
	DataDeletionRequestSupported bool   `json:"data_deletion_request_supported"`
	DataDeletionNote             string `json:"data_deletion_note"`
	AccountCreationRequired      bool   `json:"account_creation_required"`
}

// DataItem is one logical thing the SDK collects, traced back to the proto
// field(s) it derives from and projected onto each store's disclosure model.
type DataItem struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ProtoFields      []string     `json:"proto_fields"`
	Description      string       `json:"description"`
	PersonalData     bool         `json:"personal_data"`
	LinkedToIdentity bool         `json:"linked_to_identity"`
	UsedForTracking  bool         `json:"used_for_tracking"`
	Optional         bool         `json:"optional"`
	DefaultCollected bool         `json:"default_collected"`
	Purposes         []string     `json:"purposes"`
	IOS              *IOSMapping  `json:"ios,omitempty"`
	Android          *PlayMapping `json:"android,omitempty"`
}

// IOSMapping projects a data item onto Apple's NSPrivacyCollectedDataType model.
type IOSMapping struct {
	CollectedDataType string   `json:"collected_data_type"`
	Purposes          []string `json:"purposes"`
}

// PlayMapping projects a data item onto Google Play's Data-Safety model.
type PlayMapping struct {
	Category string   `json:"category"`
	DataType string   `json:"data_type"`
	Purposes []string `json:"purposes"`
}

// ReasonAPI is one Apple "required reason" API the SDK invokes, with the chosen
// reason code(s) and the SDK source that triggers it.
type ReasonAPI struct {
	APICategory   string   `json:"api_category"`
	Reasons       []string `json:"reasons"`
	SDKSource     string   `json:"sdk_source"`
	Justification string   `json:"justification"`
}

// Canonical returns the embedded, validated kseal data contract.
func Canonical() (*Contract, error) {
	return parse(canonicalJSON, "<embedded>")
}

// Load reads and validates a contract from a file path. An empty path returns
// the embedded canonical contract.
func Load(path string) (*Contract, error) {
	if strings.TrimSpace(path) == "" {
		return Canonical()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read data contract: %w", err)
	}
	return parse(data, path)
}

func parse(data []byte, src string) (*Contract, error) {
	var c Contract
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse data contract (%s): %w", src, err)
	}
	if problems := c.validate(); len(problems) > 0 {
		return nil, fmt.Errorf("data contract (%s) is invalid: %s", src, strings.Join(problems, "; "))
	}
	return &c, nil
}

// validate enforces the structural invariants the generators rely on. A broken
// contract is a build-time defect, so it surfaces as an error rather than
// producing a misleading store disclosure.
func (c *Contract) validate() []string {
	var problems []string
	if c.Schema == "" {
		problems = append(problems, "schema is required")
	}
	if c.SDK == "" {
		problems = append(problems, "sdk is required")
	}
	if len(c.Collected) == 0 {
		problems = append(problems, "collected must list at least one data item")
	}
	seenID := map[string]bool{}
	seenField := map[string]bool{}
	for _, it := range c.Collected {
		switch {
		case it.ID == "":
			problems = append(problems, "a collected item is missing id")
		case seenID[it.ID]:
			problems = append(problems, fmt.Sprintf("duplicate collected id %q", it.ID))
		}
		seenID[it.ID] = true
		if it.Name == "" {
			problems = append(problems, fmt.Sprintf("collected %q is missing name", it.ID))
		}
		if len(it.ProtoFields) == 0 {
			problems = append(problems, fmt.Sprintf("collected %q must reference at least one proto field", it.ID))
		}
		for _, f := range it.ProtoFields {
			if seenField[f] {
				problems = append(problems, fmt.Sprintf("proto field %q mapped by more than one collected item", f))
			}
			seenField[f] = true
		}
		// Items that are personal data and surfaced to a store must carry the
		// store projection so the generators do not silently drop a disclosure.
		if it.PersonalData {
			if it.IOS == nil && it.Android == nil {
				problems = append(problems, fmt.Sprintf("personal-data item %q has no ios/android store mapping", it.ID))
			}
			if it.IOS != nil && it.IOS.CollectedDataType == "" {
				problems = append(problems, fmt.Sprintf("item %q ios mapping is missing collected_data_type", it.ID))
			}
			if it.Android != nil && (it.Android.Category == "" || it.Android.DataType == "") {
				problems = append(problems, fmt.Sprintf("item %q android mapping is missing category/data_type", it.ID))
			}
		}
	}
	for _, r := range c.IOSReasonAPIs {
		if r.APICategory == "" {
			problems = append(problems, "an ios_required_reason_apis entry is missing api_category")
		}
		if len(r.Reasons) == 0 {
			problems = append(problems, fmt.Sprintf("required-reason API %q has no reason codes", r.APICategory))
		}
	}
	return problems
}

// PersonalDataItems returns the collected items that are user/personal data, in
// contract order. Build/policy hashes and coarse timestamps are excluded
// because they identify the artifact or envelope, not the user or device.
func (c *Contract) PersonalDataItems() []DataItem {
	out := make([]DataItem, 0, len(c.Collected))
	for _, it := range c.Collected {
		if it.PersonalData {
			out = append(out, it)
		}
	}
	return out
}

// ProtoFields returns the sorted union of every proto field the contract
// declares as collected. Used by the drift test against telemetry.proto.
func (c *Contract) ProtoFields() []string {
	set := map[string]struct{}{}
	for _, it := range c.Collected {
		for _, f := range it.ProtoFields {
			set[f] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}
