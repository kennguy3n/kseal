package compliance

import (
	"fmt"
	"strconv"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"google.golang.org/protobuf/proto"
)

// clampPageSize bounds a requested page size to a sane default and ceiling.
func clampPageSize(n int) int {
	switch {
	case n <= 0:
		return 50
	case n > 500:
		return 500
	default:
		return n
	}
}

// matchAuditFilter reports whether ev satisfies every set field of f.
func matchAuditFilter(ev *ksealv1.AuditEvent, f AuditFilter) bool {
	if f.Action != "" && ev.Action != f.Action {
		return false
	}
	if f.ResourceType != "" && ev.ResourceType != f.ResourceType {
		return false
	}
	if f.FromMillis > 0 && ev.CreatedAt < f.FromMillis {
		return false
	}
	if f.ToMillis > 0 && ev.CreatedAt > f.ToMillis {
		return false
	}
	return true
}

// rollbackEvent renders the human-readable last-transition string for a
// rollback, including the reason when present.
func rollbackEvent(reason string) string {
	if reason == "" {
		return "rolled back to stable"
	}
	return "rolled back to stable: " + reason
}

// killSwitchEntry builds the audit entry for an issued kill switch. It records
// the scope, command, and version — never PII.
func killSwitchEntry(in KillSwitchInput, version int64) Entry {
	md := map[string]string{
		"command": commandName(in.Command),
		"version": strconv.FormatInt(version, 10),
	}
	if in.AppID != "" {
		md["app_id"] = in.AppID
	}
	if in.BuildHash != "" {
		md["build_hash"] = in.BuildHash
	}
	return Entry{
		Action:       "killswitch.issue",
		ResourceType: "kill_switch",
		ResourceID:   killSwitchResourceID(in.AppID, in.BuildHash),
		ActorKeyID:   in.ActorKeyID,
		Metadata:     md,
	}
}

// canaryEntry builds an audit entry for a canary transition.
func canaryEntry(action, appID, actorKeyID string, md map[string]string) Entry {
	return Entry{
		Action:       action,
		ResourceType: "canary",
		ResourceID:   appID,
		ActorKeyID:   actorKeyID,
		Metadata:     md,
	}
}

func killSwitchResourceID(appID, buildHash string) string {
	switch {
	case appID == "" && buildHash == "":
		return "tenant"
	case buildHash == "":
		return appID
	default:
		return fmt.Sprintf("%s/%s", appID, buildHash)
	}
}

func commandName(c ksealv1.KillSwitchCommand) string {
	switch c {
	case ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_ENABLE:
		return "enable"
	case ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_DISABLE:
		return "disable"
	default:
		return "unspecified"
	}
}

func cloneMeta(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneAudit(e *ksealv1.AuditEvent) *ksealv1.AuditEvent {
	return proto.Clone(e).(*ksealv1.AuditEvent)
}

func cloneDataProc(r *ksealv1.DataProcessingRecord) *ksealv1.DataProcessingRecord {
	return proto.Clone(r).(*ksealv1.DataProcessingRecord)
}

func cloneKillSwitch(k *ksealv1.SignedKillSwitch) *ksealv1.SignedKillSwitch {
	return proto.Clone(k).(*ksealv1.SignedKillSwitch)
}

func cloneCanary(c *ksealv1.CanaryStatus) *ksealv1.CanaryStatus {
	return proto.Clone(c).(*ksealv1.CanaryStatus)
}
