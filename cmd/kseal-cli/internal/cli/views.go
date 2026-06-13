package cli

import (
	"strconv"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// View structs are the stable JSON projections of proto messages. Using
// explicit, snake_case-tagged structs (rather than protojson) keeps `--output
// json` shapes deterministic, documented, and free of any secret material.

type tenantView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	Tier      string `json:"tier"`
	Status    string `json:"status"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

func newTenantView(t *ksealv1.Tenant) tenantView {
	return tenantView{
		ID: t.GetId(), Name: t.GetName(), Slug: t.GetSlug(), Tier: t.GetTier(),
		Status: t.GetStatus(), CreatedAt: t.GetCreatedAt(), UpdatedAt: t.GetUpdatedAt(),
	}
}

func tenantTable(ts []*ksealv1.Tenant) table {
	tbl := table{Headers: []string{"ID", "NAME", "SLUG", "TIER", "STATUS"}}
	for _, t := range ts {
		tbl.Rows = append(tbl.Rows, []string{t.GetId(), t.GetName(), t.GetSlug(), t.GetTier(), t.GetStatus()})
	}
	return tbl
}

type appView struct {
	ID                string   `json:"id"`
	TenantID          string   `json:"tenant_id"`
	Name              string   `json:"name"`
	Platform          string   `json:"platform"`
	PackageID         string   `json:"package_id"`
	SigningIdentities []string `json:"signing_identities"`
	Status            string   `json:"status"`
	CreatedAt         int64    `json:"created_at"`
	UpdatedAt         int64    `json:"updated_at"`
}

func newAppView(a *ksealv1.App) appView {
	ids := a.GetSigningIdentities()
	if ids == nil {
		ids = []string{}
	}
	return appView{
		ID: a.GetId(), TenantID: a.GetTenantId(), Name: a.GetName(),
		Platform: a.GetPlatform().String(), PackageID: a.GetPackageId(),
		SigningIdentities: ids, Status: a.GetStatus(),
		CreatedAt: a.GetCreatedAt(), UpdatedAt: a.GetUpdatedAt(),
	}
}

func appTable(as []*ksealv1.App) table {
	tbl := table{Headers: []string{"ID", "NAME", "PLATFORM", "PACKAGE_ID", "STATUS"}}
	for _, a := range as {
		tbl.Rows = append(tbl.Rows, []string{a.GetId(), a.GetName(), a.GetPlatform().String(), a.GetPackageId(), a.GetStatus()})
	}
	return tbl
}

type buildView struct {
	ID                  string `json:"id"`
	TenantID            string `json:"tenant_id"`
	AppID               string `json:"app_id"`
	BuildHash           string `json:"build_hash"`
	VersionName         string `json:"version_name"`
	VersionCode         int64  `json:"version_code"`
	ProtectionProfileID string `json:"protection_profile_id"`
	Manifest            string `json:"manifest"`
	CreatedAt           int64  `json:"created_at"`
}

func newBuildView(b *ksealv1.Build) buildView {
	return buildView{
		ID: b.GetId(), TenantID: b.GetTenantId(), AppID: b.GetAppId(),
		BuildHash: b.GetBuildHash(), VersionName: b.GetVersionName(),
		VersionCode: b.GetVersionCode(), ProtectionProfileID: b.GetProtectionProfileId(),
		Manifest: b.GetManifest(), CreatedAt: b.GetCreatedAt(),
	}
}

func buildTable(bs []*ksealv1.Build) table {
	tbl := table{Headers: []string{"ID", "APP_ID", "BUILD_HASH", "VERSION", "CODE"}}
	for _, b := range bs {
		tbl.Rows = append(tbl.Rows, []string{b.GetId(), b.GetAppId(), b.GetBuildHash(), b.GetVersionName(), strconv.FormatInt(b.GetVersionCode(), 10)})
	}
	return tbl
}

type policyView struct {
	ID              string   `json:"id"`
	TenantID        string   `json:"tenant_id"`
	AppID           string   `json:"app_id"`
	Name            string   `json:"name"`
	Version         int32    `json:"version"`
	EnforcementMode string   `json:"enforcement_mode"`
	Rules           string   `json:"rules"`
	RiskThresholds  string   `json:"risk_thresholds"`
	ModulesEnabled  []string `json:"modules_enabled"`
	IsActive        bool     `json:"is_active"`
	CreatedAt       int64    `json:"created_at"`
	UpdatedAt       int64    `json:"updated_at"`
}

func newPolicyView(p *ksealv1.Policy) policyView {
	mods := p.GetModulesEnabled()
	if mods == nil {
		mods = []string{}
	}
	return policyView{
		ID: p.GetId(), TenantID: p.GetTenantId(), AppID: p.GetAppId(), Name: p.GetName(),
		Version: p.GetVersion(), EnforcementMode: p.GetEnforcementMode().String(),
		Rules: p.GetRules(), RiskThresholds: p.GetRiskThresholds(), ModulesEnabled: mods,
		IsActive: p.GetIsActive(), CreatedAt: p.GetCreatedAt(), UpdatedAt: p.GetUpdatedAt(),
	}
}

func policyTable(ps []*ksealv1.Policy) table {
	tbl := table{Headers: []string{"ID", "NAME", "VERSION", "MODE", "ACTIVE"}}
	for _, p := range ps {
		tbl.Rows = append(tbl.Rows, []string{p.GetId(), p.GetName(), strconv.Itoa(int(p.GetVersion())), p.GetEnforcementMode().String(), strconv.FormatBool(p.GetIsActive())})
	}
	return tbl
}

type profileView struct {
	ID             string   `json:"id"`
	TenantID       string   `json:"tenant_id"`
	Name           string   `json:"name"`
	ModulesEnabled []string `json:"modules_enabled"`
	DefaultMode    string   `json:"default_mode"`
	CreatedAt      int64    `json:"created_at"`
}

func newProfileView(p *ksealv1.ProtectionProfile) profileView {
	mods := p.GetModulesEnabled()
	if mods == nil {
		mods = []string{}
	}
	return profileView{
		ID: p.GetId(), TenantID: p.GetTenantId(), Name: p.GetName(),
		ModulesEnabled: mods, DefaultMode: p.GetDefaultMode().String(), CreatedAt: p.GetCreatedAt(),
	}
}

func profileTable(ps []*ksealv1.ProtectionProfile) table {
	tbl := table{Headers: []string{"ID", "NAME", "DEFAULT_MODE", "MODULES"}}
	for _, p := range ps {
		mods := ""
		for i, m := range p.GetModulesEnabled() {
			if i > 0 {
				mods += ","
			}
			mods += m
		}
		tbl.Rows = append(tbl.Rows, []string{p.GetId(), p.GetName(), p.GetDefaultMode().String(), mods})
	}
	return tbl
}

type webhookView struct {
	ID           string   `json:"id"`
	TenantID     string   `json:"tenant_id"`
	URL          string   `json:"url"`
	EventTypes   []string `json:"event_types"`
	SigningKeyID string   `json:"signing_key_id"`
	IsActive     bool     `json:"is_active"`
	CreatedAt    int64    `json:"created_at"`
}

func newWebhookView(w *ksealv1.Webhook) webhookView {
	types := make([]string, 0, len(w.GetEventTypes()))
	for _, t := range w.GetEventTypes() {
		types = append(types, t.String())
	}
	return webhookView{
		ID: w.GetId(), TenantID: w.GetTenantId(), URL: w.GetUrl(),
		EventTypes: types, SigningKeyID: w.GetSigningKeyId(),
		IsActive: w.GetIsActive(), CreatedAt: w.GetCreatedAt(),
	}
}

func webhookTable(ws []*ksealv1.Webhook) table {
	tbl := table{Headers: []string{"ID", "URL", "ACTIVE", "SIGNING_KEY_ID"}}
	for _, w := range ws {
		tbl.Rows = append(tbl.Rows, []string{w.GetId(), w.GetUrl(), strconv.FormatBool(w.GetIsActive()), w.GetSigningKeyId()})
	}
	return tbl
}

type eventView struct {
	ID              string `json:"id"`
	TenantID        string `json:"tenant_id"`
	AppID           string `json:"app_id"`
	EventType       string `json:"event_type"`
	RiskLevel       string `json:"risk_level"`
	RiskBits        uint64 `json:"risk_bits"`
	Confidence      string `json:"confidence"`
	AppBuildHash    string `json:"app_build_hash"`
	PolicyHash      string `json:"policy_hash"`
	Timestamp       int64  `json:"timestamp"`
	CountryOrRegion string `json:"country_or_region,omitempty"`
}

func newEventView(e *ksealv1.EventRecord) eventView {
	return eventView{
		ID: e.GetId(), TenantID: e.GetTenantId(), AppID: e.GetAppId(),
		EventType: e.GetEventType().String(), RiskLevel: e.GetRiskLevel().String(),
		RiskBits: e.GetRiskBits(), Confidence: e.GetConfidence().String(),
		AppBuildHash: e.GetAppBuildHash(), PolicyHash: e.GetPolicyHash(),
		Timestamp: e.GetTimestamp(), CountryOrRegion: e.GetCountryOrRegion(),
	}
}

// eventColumn is the single source of truth for the columns rendered by both
// `events query` (a buffered, dynamically-aligned tabwriter table) and
// `events tail` (a fixed-width streaming layout). width is the minimum field
// width used only by the streaming tail; the buffered table sizes columns
// dynamically and ignores it.
type eventColumn struct {
	header string
	width  int
	value  func(*ksealv1.EventRecord) string
}

// eventColumns sizes its widths to the widest realistic value per column
// (unix-millis timestamps and the longest proto enum names) so that streamed
// `tail` rows stay aligned; an over-long value degrades gracefully (it pushes
// that one row's later columns right) rather than corrupting data.
var eventColumns = []eventColumn{
	{"TIMESTAMP", 13, func(e *ksealv1.EventRecord) string { return strconv.FormatInt(e.GetTimestamp(), 10) }},
	{"ID", 22, func(e *ksealv1.EventRecord) string { return e.GetId() }},
	{"APP_ID", 22, func(e *ksealv1.EventRecord) string { return e.GetAppId() }},
	{"TYPE", 29, func(e *ksealv1.EventRecord) string { return e.GetEventType().String() }},
	{"RISK_LEVEL", 23, func(e *ksealv1.EventRecord) string { return e.GetRiskLevel().String() }},
	{"CONFIDENCE", 0, func(e *ksealv1.EventRecord) string { return e.GetConfidence().String() }},
}

func eventColumnHeaders() []string {
	h := make([]string, len(eventColumns))
	for i, c := range eventColumns {
		h[i] = c.header
	}
	return h
}

func eventRow(e *ksealv1.EventRecord) []string {
	r := make([]string, len(eventColumns))
	for i, c := range eventColumns {
		r[i] = c.value(e)
	}
	return r
}

func eventTable(es []*ksealv1.EventRecord) table {
	tbl := table{Headers: eventColumnHeaders()}
	for _, e := range es {
		tbl.Rows = append(tbl.Rows, eventRow(e))
	}
	return tbl
}
