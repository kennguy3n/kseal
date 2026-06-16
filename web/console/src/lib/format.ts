import {
  Confidence,
  EnforcementMode,
  EventType,
  Platform,
  TrustLevel,
} from "../gen/kseal/v1/common_pb";
import {
  CanaryState,
  KillSwitchCommand,
} from "../gen/kseal/v1/compliance_pb";

export const platformLabels: Record<Platform, string> = {
  [Platform.UNSPECIFIED]: "Unspecified",
  [Platform.ANDROID]: "Android",
  [Platform.IOS]: "iOS",
};

export const eventTypeLabels: Record<EventType, string> = {
  [EventType.UNSPECIFIED]: "Unspecified",
  [EventType.RUNTIME_TAMPER]: "Runtime tamper",
  [EventType.DEBUGGER]: "Debugger",
  [EventType.ROOT_RISK]: "Root / jailbreak",
  [EventType.ATTESTATION_FAIL]: "Attestation fail",
  [EventType.NETWORK_MITM]: "Network MITM",
  [EventType.POLICY_DECISION]: "Policy decision",
  [EventType.HOOKING_DETECTED]: "Hooking detected",
  [EventType.APP_INTEGRITY_FAIL]: "App integrity fail",
  [EventType.ENVIRONMENT_RISK]: "Environment risk",
  [EventType.SCREEN_CAPTURE]: "Screen capture",
  [EventType.OVERLAY_ABUSE]: "Overlay abuse",
  [EventType.ACCESSIBILITY_ABUSE]: "Accessibility abuse",
  [EventType.MALICIOUS_IME]: "Malicious keyboard",
  [EventType.REMOTE_ACCESS]: "Remote access",
};

export const trustLevelLabels: Record<TrustLevel, string> = {
  [TrustLevel.UNSPECIFIED]: "Unspecified",
  [TrustLevel.TRUSTED]: "Trusted",
  [TrustLevel.LOW_RISK]: "Low risk",
  [TrustLevel.MEDIUM_RISK]: "Medium risk",
  [TrustLevel.HIGH_RISK]: "High risk",
  [TrustLevel.CRITICAL]: "Critical",
};

export const enforcementModeLabels: Record<EnforcementMode, string> = {
  [EnforcementMode.UNSPECIFIED]: "Unspecified",
  [EnforcementMode.OBSERVE]: "Observe",
  [EnforcementMode.STEP_UP]: "Step-up",
  [EnforcementMode.BLOCK]: "Block",
};

export const confidenceLabels: Record<Confidence, string> = {
  [Confidence.UNSPECIFIED]: "Unspecified",
  [Confidence.LOW]: "Low",
  [Confidence.MEDIUM]: "Medium",
  [Confidence.HIGH]: "High",
};

// Tailwind classes for a risk badge, escalating with severity. Each tone keeps
// WCAG-AA text contrast in both themes: a darker text shade over a light tint
// on the light theme, and the lighter shade over a deeper tint in the dark.
export function riskLevelTone(level: TrustLevel): string {
  switch (level) {
    case TrustLevel.TRUSTED:
      return "bg-emerald-500/10 text-emerald-700 border-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-300";
    case TrustLevel.LOW_RISK:
      return "bg-sky-500/10 text-sky-700 border-sky-500/30 dark:bg-sky-500/15 dark:text-sky-300";
    case TrustLevel.MEDIUM_RISK:
      return "bg-amber-500/10 text-amber-700 border-amber-500/30 dark:bg-amber-500/15 dark:text-amber-300";
    case TrustLevel.HIGH_RISK:
      return "bg-orange-500/10 text-orange-700 border-orange-500/30 dark:bg-orange-500/15 dark:text-orange-300";
    case TrustLevel.CRITICAL:
      return "bg-rose-500/10 text-rose-700 border-rose-500/30 dark:bg-rose-500/15 dark:text-rose-300";
    default:
      return "bg-fg-subtle/10 text-fg border-line-strong dark:bg-fg-subtle/15";
  }
}

// The canonical kill switch resolves an effective command per scope. ENABLE
// (and the UNSPECIFIED default) means protection is armed; DISABLE means
// enforcement has been remotely disabled.
export const killSwitchCommandLabels: Record<KillSwitchCommand, string> = {
  [KillSwitchCommand.UNSPECIFIED]: "Armed",
  [KillSwitchCommand.ENABLE]: "Armed",
  [KillSwitchCommand.DISABLE]: "Disabled",
};

// Tone for a kill-switch badge: enabled/armed (enforcing) is the healthy state.
export function killSwitchCommandTone(command: KillSwitchCommand): string {
  switch (command) {
    case KillSwitchCommand.DISABLE:
      return "bg-rose-500/10 text-rose-700 border-rose-500/30 dark:bg-rose-500/15 dark:text-rose-300";
    default:
      return "bg-emerald-500/10 text-emerald-700 border-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-300";
  }
}

export const canaryStateLabels: Record<CanaryState, string> = {
  [CanaryState.UNSPECIFIED]: "Unknown",
  [CanaryState.ACTIVE]: "Active",
  [CanaryState.PROMOTED]: "Promoted",
  [CanaryState.ROLLED_BACK]: "Rolled back",
};

export function canaryStateTone(state: CanaryState): string {
  switch (state) {
    case CanaryState.ACTIVE:
      return "bg-sky-500/10 text-sky-700 border-sky-500/30 dark:bg-sky-500/15 dark:text-sky-300";
    case CanaryState.PROMOTED:
      return "bg-emerald-500/10 text-emerald-700 border-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-300";
    case CanaryState.ROLLED_BACK:
      return "bg-rose-500/10 text-rose-700 border-rose-500/30 dark:bg-rose-500/15 dark:text-rose-300";
    default:
      return "bg-fg-subtle/10 text-fg border-line-strong dark:bg-fg-subtle/15";
  }
}

// Formats a 0..1 rate as a percentage with one decimal (e.g. 0.0123 -> "1.2%").
export function formatRate(rate: number): string {
  if (!Number.isFinite(rate)) return "—";
  return `${(rate * 100).toFixed(1)}%`;
}

// Accepts unix-millis as bigint (proto int64) or number and renders a stable,
// locale-independent UTC timestamp. Returns "—" for zero/empty values.
export function formatTimestamp(ms: bigint | number): string {
  const n = typeof ms === "bigint" ? Number(ms) : ms;
  if (!Number.isFinite(n) || n <= 0) return "—";
  // Always render to second precision so rows are formatted consistently
  // regardless of sub-second timestamp components.
  return new Date(n).toISOString().replace("T", " ").replace(/\.\d{3}Z$/, "Z");
}

// Renders a unix-seconds timestamp (the control-plane registry emits
// `EXTRACT(EPOCH ...)` seconds for created_at/updated_at on apps, builds,
// webhooks, SIEM connectors, etc.). Telemetry events and compliance records use
// millis — use formatTimestamp for those. Returns "—" for zero/empty values.
export function formatEpochSeconds(seconds: bigint | number): string {
  const n = typeof seconds === "bigint" ? Number(seconds) : seconds;
  if (!Number.isFinite(n) || n <= 0) return "—";
  return formatTimestamp(n * 1000);
}
