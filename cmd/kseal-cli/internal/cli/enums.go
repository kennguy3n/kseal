package cli

import (
	"fmt"
	"strings"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// parsePlatform accepts short ("android", "ios") or full enum names.
func parsePlatform(s string) (ksealv1.Platform, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ANDROID", "PLATFORM_ANDROID":
		return ksealv1.Platform_PLATFORM_ANDROID, nil
	case "IOS", "PLATFORM_IOS":
		return ksealv1.Platform_PLATFORM_IOS, nil
	default:
		return ksealv1.Platform_PLATFORM_UNSPECIFIED, fmt.Errorf("invalid platform %q: want android|ios", s)
	}
}

// eventTypeNames is the accepted short alias -> enum mapping for event types.
var eventTypeNames = map[string]ksealv1.EventType{
	"RUNTIME_TAMPER":     ksealv1.EventType_EVENT_TYPE_RUNTIME_TAMPER,
	"DEBUGGER":           ksealv1.EventType_EVENT_TYPE_DEBUGGER,
	"ROOT_RISK":          ksealv1.EventType_EVENT_TYPE_ROOT_RISK,
	"ATTESTATION_FAIL":   ksealv1.EventType_EVENT_TYPE_ATTESTATION_FAIL,
	"NETWORK_MITM":       ksealv1.EventType_EVENT_TYPE_NETWORK_MITM,
	"POLICY_DECISION":    ksealv1.EventType_EVENT_TYPE_POLICY_DECISION,
	"HOOKING_DETECTED":   ksealv1.EventType_EVENT_TYPE_HOOKING_DETECTED,
	"APP_INTEGRITY_FAIL": ksealv1.EventType_EVENT_TYPE_APP_INTEGRITY_FAIL,
	"ENVIRONMENT_RISK":   ksealv1.EventType_EVENT_TYPE_ENVIRONMENT_RISK,
}

func parseEventType(s string) (ksealv1.EventType, error) {
	key := strings.ToUpper(strings.TrimSpace(s))
	key = strings.TrimPrefix(key, "EVENT_TYPE_")
	if t, ok := eventTypeNames[key]; ok {
		return t, nil
	}
	return ksealv1.EventType_EVENT_TYPE_UNSPECIFIED, fmt.Errorf("invalid event type %q", s)
}

func parseEventTypes(ss []string) ([]ksealv1.EventType, error) {
	out := make([]ksealv1.EventType, 0, len(ss))
	for _, s := range ss {
		t, err := parseEventType(s)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// trustLevelNames is the accepted short alias -> enum mapping for risk levels.
var trustLevelNames = map[string]ksealv1.TrustLevel{
	"TRUSTED":     ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED,
	"LOW_RISK":    ksealv1.TrustLevel_TRUST_LEVEL_LOW_RISK,
	"MEDIUM_RISK": ksealv1.TrustLevel_TRUST_LEVEL_MEDIUM_RISK,
	"HIGH_RISK":   ksealv1.TrustLevel_TRUST_LEVEL_HIGH_RISK,
	"CRITICAL":    ksealv1.TrustLevel_TRUST_LEVEL_CRITICAL,
}

func parseTrustLevel(s string) (ksealv1.TrustLevel, error) {
	key := strings.ToUpper(strings.TrimSpace(s))
	key = strings.TrimPrefix(key, "TRUST_LEVEL_")
	if l, ok := trustLevelNames[key]; ok {
		return l, nil
	}
	return ksealv1.TrustLevel_TRUST_LEVEL_UNSPECIFIED, fmt.Errorf("invalid risk level %q", s)
}

func parseTrustLevels(ss []string) ([]ksealv1.TrustLevel, error) {
	out := make([]ksealv1.TrustLevel, 0, len(ss))
	for _, s := range ss {
		l, err := parseTrustLevel(s)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, nil
}
