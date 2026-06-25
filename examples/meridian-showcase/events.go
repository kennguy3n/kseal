package main

import (
	"fmt"
	"log"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// eventsPerApp is how many telemetry events each app contributes. The server
// derives each event's risk level from its wire bits, so the distribution of
// templates below shapes the trust-level mix shown across the console.
const eventsPerApp = 220

// regions are coarse geographies attached to events (k-anonymity bucket).
var regions = []string{"US", "GB", "DE", "FR", "BR", "IN", "NG", "SG", "JP", "CA", "AU", "MX", "ZA", "AE"}

// evTemplate is a class of telemetry event: an event type, the device wire bits
// that justify it, a reporting confidence, and a sampling weight. The bits are
// chosen so the server-computed risk level is coherent with the event type
// (e.g. a repackaged-build APP_INTEGRITY_FAIL scores CRITICAL). repacked marks
// the templates that make up the repackaged-build fraud campaign; their events
// are attributed to the app's repacked build hash (the one the kill switch
// targets) instead of the latest release.
type evTemplate struct {
	typ      ksealv1.EventType
	wire     uint64
	conf     ksealv1.Confidence
	weight   int
	repacked bool
}

var eventTemplates = []evTemplate{
	// The bulk: clean payment authorizations (TRUSTED).
	{ksealv1.EventType_EVENT_TYPE_POLICY_DECISION, 0, ksealv1.Confidence_CONFIDENCE_HIGH, 92, false},
	// Low-severity single signals.
	{ksealv1.EventType_EVENT_TYPE_ROOT_RISK, bits(wRoot, wJailbreak), ksealv1.Confidence_CONFIDENCE_MEDIUM, 10, false},
	{ksealv1.EventType_EVENT_TYPE_DEBUGGER, bits(wDebugger), ksealv1.Confidence_CONFIDENCE_MEDIUM, 5, false},
	{ksealv1.EventType_EVENT_TYPE_HOOKING_DETECTED, bits(wHooking), ksealv1.Confidence_CONFIDENCE_MEDIUM, 6, false},
	{ksealv1.EventType_EVENT_TYPE_NETWORK_MITM, bits(wNetworkMITM, wUserCA), ksealv1.Confidence_CONFIDENCE_MEDIUM, 5, false},
	{ksealv1.EventType_EVENT_TYPE_ENVIRONMENT_RISK, bits(wEnvironment, wEmulator), ksealv1.Confidence_CONFIDENCE_LOW, 4, false},
	{ksealv1.EventType_EVENT_TYPE_SCREEN_CAPTURE, bits(wScreenCapture), ksealv1.Confidence_CONFIDENCE_MEDIUM, 4, false},
	{ksealv1.EventType_EVENT_TYPE_OVERLAY_ABUSE, bits(wOverlay), ksealv1.Confidence_CONFIDENCE_MEDIUM, 4, false},
	{ksealv1.EventType_EVENT_TYPE_ACCESSIBILITY_ABUSE, bits(wAccessibility), ksealv1.Confidence_CONFIDENCE_MEDIUM, 3, false},
	{ksealv1.EventType_EVENT_TYPE_MALICIOUS_IME, bits(wMaliciousIME), ksealv1.Confidence_CONFIDENCE_LOW, 3, false},
	{ksealv1.EventType_EVENT_TYPE_REMOTE_ACCESS, bits(wRemoteAccess), ksealv1.Confidence_CONFIDENCE_MEDIUM, 3, false},
	// Medium severity.
	{ksealv1.EventType_EVENT_TYPE_RUNTIME_TAMPER, bits(wTamper), ksealv1.Confidence_CONFIDENCE_HIGH, 5, false},
	{ksealv1.EventType_EVENT_TYPE_ATTESTATION_FAIL, bits(wAttestFail), ksealv1.Confidence_CONFIDENCE_HIGH, 5, false},
	{ksealv1.EventType_EVENT_TYPE_APP_INTEGRITY_FAIL, bits(wAppIntegrity), ksealv1.Confidence_CONFIDENCE_HIGH, 4, false},
	// High severity (combined signals).
	{ksealv1.EventType_EVENT_TYPE_REMOTE_ACCESS, bits(wRemoteAccess, wRoot, wHooking), ksealv1.Confidence_CONFIDENCE_HIGH, 3, false},
	{ksealv1.EventType_EVENT_TYPE_ATTESTATION_FAIL, bits(wAttestFail, wRoot), ksealv1.Confidence_CONFIDENCE_HIGH, 2, false},
	// Critical: the repackaged-build fraud campaign (attributed to repackedBuild).
	{ksealv1.EventType_EVENT_TYPE_APP_INTEGRITY_FAIL, bits(wTamper, wAttestFail, wRoot), ksealv1.Confidence_CONFIDENCE_HIGH, 3, true},
	{ksealv1.EventType_EVENT_TYPE_ATTESTATION_FAIL, bits(wAttestFail, wTamper), ksealv1.Confidence_CONFIDENCE_HIGH, 2, true},
}

func (s *seeder) weightedTemplate(total int) *evTemplate {
	r := s.rng.Intn(total)
	for i := range eventTemplates {
		r -= eventTemplates[i].weight
		if r < 0 {
			return &eventTemplates[i]
		}
	}
	return &eventTemplates[0]
}

func (s *seeder) ingestEvents(tenantID string, a appSeed) error {
	total := 0
	for _, t := range eventTemplates {
		total += t.weight
	}
	nowMs := time.Now().UnixMilli()

	events := make([]*ksealv1.TelemetryEvent, 0, eventsPerApp)
	for i := 0; i < eventsPerApp; i++ {
		t := s.weightedTemplate(total)
		// Spread each event uniformly over the last 23h.
		offsetMs := int64(s.rng.Intn(23*3600)) * 1000
		region := regions[s.rng.Intn(len(regions))]
		// The repackaged-build fraud campaign reports against the malicious build
		// hash the kill switch targets; everything else against the latest build.
		buildHash := a.currentBuild
		if t.repacked && a.repackedBuild != "" {
			buildHash = a.repackedBuild
		}
		ev := &ksealv1.TelemetryEvent{
			EventType:        t.typ,
			RiskBits:         t.wire,
			Confidence:       t.conf,
			AppBuildHash:     buildHash,
			PolicyHash:       policyHash,
			CoarseTimeBucket: nowMs - offsetMs,
			CountryOrRegion:  &region,
		}
		events = append(events, ev)
	}

	// Submit in batches over the public device-plane ingest API.
	const batchSize = 100
	var accepted, rejected int32
	for start := 0; start < len(events); start += batchSize {
		end := start + batchSize
		if end > len(events) {
			end = len(events)
		}
		raw, err := proto.Marshal(&ksealv1.TelemetryBatch{
			Events:      events[start:end],
			SdkVersion:  "kseal-android/4.2.0",
			Compression: ksealv1.Compression_COMPRESSION_NONE,
			Platform:    a.app.Platform,
		})
		if err != nil {
			return fmt.Errorf("marshal batch: %w", err)
		}
		req := connect.NewRequest(&ksealv1.SubmitTelemetryRequest{
			TenantId:        tenantID,
			AppId:           a.app.Id,
			CompressedBatch: raw,
			Compression:     ksealv1.Compression_COMPRESSION_NONE,
		})
		req.Header().Set("Authorization", "Bearer "+s.apiKey)
		resp, err := s.ingest.SubmitTelemetry(s.ctx, req)
		if err != nil {
			return fmt.Errorf("submit telemetry: %w", err)
		}
		accepted += resp.Msg.Accepted
		rejected += resp.Msg.Rejected
	}
	log.Printf("events: %s accepted=%d rejected=%d", a.app.Name, accepted, rejected)
	return nil
}
