package cli

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/kennguy3n/kseal/cli/internal/compliancepb"
)

// The view structs below are plain JSON shapes derived from the stream-local
// proto messages. Rendering through these (rather than the generated proto
// structs) keeps `--output json` stable and free of protobuf-internal fields,
// and lets the table renderer stay compact.

type auditEntryView struct {
	ID         string `json:"id"`
	TimeBucket int64  `json:"time_bucket"`
	Actor      string `json:"actor"`
	Action     string `json:"action"`
	Target     string `json:"target"`
	Detail     string `json:"detail,omitempty"`
}

type auditTrailView struct {
	Available     bool             `json:"available"`
	Entries       []auditEntryView `json:"entries"`
	NextPageToken string           `json:"next_page_token,omitempty"`
}

func newAuditTrailView(msg *compliancepb.GetAuditTrailResponse) auditTrailView {
	v := auditTrailView{Available: true, Entries: []auditEntryView{}, NextPageToken: msg.GetNextPageToken()}
	for _, e := range msg.GetEntries() {
		v.Entries = append(v.Entries, auditEntryView{
			ID: e.GetId(), TimeBucket: e.GetTimeBucket(), Actor: e.GetActor(),
			Action: e.GetAction(), Target: e.GetTarget(), Detail: e.GetDetail(),
		})
	}
	return v
}

func auditTrailTable(v auditTrailView) table {
	rows := make([][]string, 0, len(v.Entries))
	for _, e := range v.Entries {
		rows = append(rows, []string{strconv.FormatInt(e.TimeBucket, 10), e.Actor, e.Action, e.Target, e.Detail})
	}
	return table{Headers: []string{"TIME_BUCKET", "ACTOR", "ACTION", "TARGET", "DETAIL"}, Rows: rows}
}

type killSwitchView struct {
	Available     bool   `json:"available"`
	TenantID      string `json:"tenant_id"`
	AppID         string `json:"app_id,omitempty"`
	Engaged       bool   `json:"engaged"`
	Scope         string `json:"scope,omitempty"`
	Reason        string `json:"reason,omitempty"`
	PolicyHash    string `json:"policy_hash,omitempty"`
	UpdatedBucket int64  `json:"updated_bucket,omitempty"`
}

func newKillSwitchView(msg *compliancepb.GetKillSwitchStateResponse) killSwitchView {
	return killSwitchView{
		Available: true, TenantID: msg.GetTenantId(), AppID: msg.GetAppId(),
		Engaged: msg.GetEngaged(), Scope: msg.GetScope(), Reason: msg.GetReason(),
		PolicyHash: msg.GetPolicyHash(), UpdatedBucket: msg.GetUpdatedBucket(),
	}
}

func killSwitchTable(v killSwitchView) table {
	engaged := "no"
	if v.Engaged {
		engaged = "yes"
	}
	return table{Headers: []string{"FIELD", "VALUE"}, Rows: [][]string{
		{"tenant_id", v.TenantID},
		{"app_id", v.AppID},
		{"engaged", engaged},
		{"scope", v.Scope},
		{"reason", v.Reason},
		{"policy_hash", v.PolicyHash},
	}}
}

type processingRecordView struct {
	Purpose            string   `json:"purpose"`
	DataCategories     []string `json:"data_categories"`
	LegalBasis         string   `json:"legal_basis,omitempty"`
	Retention          string   `json:"retention,omitempty"`
	Processors         []string `json:"processors,omitempty"`
	EncryptedInTransit bool     `json:"encrypted_in_transit"`
	EncryptedAtRest    bool     `json:"encrypted_at_rest"`
}

type dprView struct {
	Available bool                   `json:"available"`
	TenantID  string                 `json:"tenant_id"`
	Records   []processingRecordView `json:"records"`
}

func newDPRView(msg *compliancepb.GetDataProcessingRegistryResponse) dprView {
	v := dprView{Available: true, TenantID: msg.GetTenantId(), Records: []processingRecordView{}}
	for _, r := range msg.GetRecords() {
		v.Records = append(v.Records, processingRecordView{
			Purpose: r.GetPurpose(), DataCategories: r.GetDataCategories(),
			LegalBasis: r.GetLegalBasis(), Retention: r.GetRetention(),
			Processors: r.GetProcessors(), EncryptedInTransit: r.GetEncryptedInTransit(),
			EncryptedAtRest: r.GetEncryptedAtRest(),
		})
	}
	return v
}

func dprTable(v dprView) table {
	rows := make([][]string, 0, len(v.Records))
	for _, r := range v.Records {
		rows = append(rows, []string{r.Purpose, strings.Join(r.DataCategories, ", "), r.LegalBasis, r.Retention})
	}
	return table{Headers: []string{"PURPOSE", "DATA_CATEGORIES", "LEGAL_BASIS", "RETENTION"}, Rows: rows}
}

// marshalIndent renders v as deterministic, indented JSON bytes with a trailing
// newline and no HTML escaping (matches renderJSON's wire form).
func marshalIndent(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
