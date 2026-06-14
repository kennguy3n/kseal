package cli

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// The view structs below are plain JSON shapes derived from the canonical
// ComplianceService proto messages. Rendering through these (rather than the
// generated proto structs) keeps `--output json` stable and free of
// protobuf-internal fields, and lets the table renderer stay compact.

type auditEntryView struct {
	Seq          int64             `json:"seq"`
	CreatedAt    int64             `json:"created_at"`
	ActorKeyID   string            `json:"actor_key_id"`
	Action       string            `json:"action"`
	ResourceType string            `json:"resource_type,omitempty"`
	ResourceID   string            `json:"resource_id,omitempty"`
	Hash         string            `json:"hash,omitempty"`
	PrevHash     string            `json:"prev_hash,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type auditTrailView struct {
	Available     bool             `json:"available"`
	Entries       []auditEntryView `json:"entries"`
	NextPageToken string           `json:"next_page_token,omitempty"`
}

func newAuditTrailView(msg *ksealv1.ListAuditEventsResponse) auditTrailView {
	v := auditTrailView{Available: true, Entries: []auditEntryView{}, NextPageToken: msg.GetNextPageToken()}
	for _, e := range msg.GetEvents() {
		v.Entries = append(v.Entries, auditEntryView{
			Seq: e.GetSeq(), CreatedAt: e.GetCreatedAt(), ActorKeyID: e.GetActorKeyId(),
			Action: e.GetAction(), ResourceType: e.GetResourceType(), ResourceID: e.GetResourceId(),
			Hash: e.GetHash(), PrevHash: e.GetPrevHash(), Metadata: e.GetMetadata(),
		})
	}
	return v
}

func auditTrailTable(v auditTrailView) table {
	rows := make([][]string, 0, len(v.Entries))
	for _, e := range v.Entries {
		resource := e.ResourceType
		if e.ResourceID != "" {
			resource = e.ResourceType + "/" + e.ResourceID
		}
		rows = append(rows, []string{
			strconv.FormatInt(e.Seq, 10),
			strconv.FormatInt(e.CreatedAt, 10),
			e.ActorKeyID, e.Action, resource, formatMetadataInline(e.Metadata),
		})
	}
	return table{Headers: []string{"SEQ", "CREATED_AT", "ACTOR_KEY_ID", "ACTION", "RESOURCE", "METADATA"}, Rows: rows}
}

// formatMetadataInline renders a metadata map as a deterministic, sorted
// `k=v` list so table output is stable across runs.
func formatMetadataInline(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ", ")
}

type signedKillSwitchView struct {
	Command  string `json:"command"`
	Version  int64  `json:"version"`
	IssuedAt int64  `json:"issued_at,omitempty"`
	KeyID    string `json:"key_id,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type killSwitchView struct {
	Available        bool                  `json:"available"`
	TenantID         string                `json:"tenant_id"`
	AppID            string                `json:"app_id,omitempty"`
	EffectiveCommand string                `json:"effective_command"`
	Enforcing        bool                  `json:"enforcing"`
	Active           *signedKillSwitchView `json:"active,omitempty"`
}

func newKillSwitchView(msg *ksealv1.GetKillSwitchStateResponse, tenant, appID string) killSwitchView {
	v := killSwitchView{
		Available: true, TenantID: tenant, AppID: appID,
		EffectiveCommand: killSwitchCommandLabel(msg.GetEffectiveCommand()),
		// Protection enforces normally unless the effective command disables it.
		Enforcing: msg.GetEffectiveCommand() != ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_DISABLE,
	}
	if a := msg.GetActive(); a != nil {
		v.Active = &signedKillSwitchView{
			Command:  killSwitchCommandLabel(a.GetCommand()),
			Version:  a.GetVersion(), IssuedAt: a.GetIssuedAt(),
			KeyID: a.GetKeyId(), Reason: a.GetReason(),
		}
	}
	return v
}

// killSwitchCommandLabel maps the canonical KillSwitchCommand enum to a stable
// lowercase label for CLI output.
func killSwitchCommandLabel(cmd ksealv1.KillSwitchCommand) string {
	switch cmd {
	case ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_ENABLE:
		return "enable"
	case ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_DISABLE:
		return "disable"
	default:
		return "unspecified"
	}
}

func killSwitchTable(v killSwitchView) table {
	enforcing := "no"
	if v.Enforcing {
		enforcing = "yes"
	}
	rows := [][]string{
		{"tenant_id", v.TenantID},
		{"app_id", v.AppID},
		{"effective_command", v.EffectiveCommand},
		{"enforcing", enforcing},
	}
	if v.Active != nil {
		rows = append(rows,
			[]string{"active_version", strconv.FormatInt(v.Active.Version, 10)},
			[]string{"active_key_id", v.Active.KeyID},
			[]string{"active_reason", v.Active.Reason},
		)
	}
	return table{Headers: []string{"FIELD", "VALUE"}, Rows: rows}
}

type processingRecordView struct {
	AppID             string   `json:"app_id"`
	Purpose           string   `json:"purpose"`
	DataCategories    []string `json:"data_categories"`
	LegalBasis        string   `json:"legal_basis,omitempty"`
	RetentionDays     int32    `json:"retention_days"`
	ThirdPartySharing bool     `json:"third_party_sharing"`
	UpdatedAt         int64    `json:"updated_at,omitempty"`
}

type dprView struct {
	Available bool                   `json:"available"`
	TenantID  string                 `json:"tenant_id"`
	Records   []processingRecordView `json:"records"`
}

func newDPRView(msg *ksealv1.GetDataProcessingRegistryResponse, tenant string) dprView {
	v := dprView{Available: true, TenantID: tenant, Records: []processingRecordView{}}
	for _, r := range msg.GetRecords() {
		v.Records = append(v.Records, processingRecordView{
			AppID: r.GetAppId(), Purpose: r.GetPurpose(), DataCategories: r.GetDataCategories(),
			LegalBasis: r.GetLegalBasis(), RetentionDays: r.GetRetentionDays(),
			ThirdPartySharing: r.GetThirdPartySharing(), UpdatedAt: r.GetUpdatedAt(),
		})
	}
	return v
}

func dprTable(v dprView) table {
	rows := make([][]string, 0, len(v.Records))
	for _, r := range v.Records {
		shared := "no"
		if r.ThirdPartySharing {
			shared = "yes"
		}
		rows = append(rows, []string{
			r.AppID, r.Purpose, strings.Join(r.DataCategories, ", "),
			r.LegalBasis, formatRetentionDays(r.RetentionDays), shared,
		})
	}
	return table{Headers: []string{"APP_ID", "PURPOSE", "DATA_CATEGORIES", "LEGAL_BASIS", "RETENTION", "THIRD_PARTY"}, Rows: rows}
}

// formatRetentionDays renders the retention window: a positive day count, or
// "aggregates only" when nothing is retained.
func formatRetentionDays(days int32) string {
	if days <= 0 {
		return "aggregates only"
	}
	return strconv.FormatInt(int64(days), 10) + " days"
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
