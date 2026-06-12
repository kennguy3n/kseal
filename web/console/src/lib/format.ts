import {
  Confidence,
  EnforcementMode,
  EventType,
  Platform,
  TrustLevel,
} from "../gen/kseal/v1/common_pb";

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

// Tailwind classes for a risk badge, escalating with severity.
export function riskLevelTone(level: TrustLevel): string {
  switch (level) {
    case TrustLevel.TRUSTED:
      return "bg-emerald-500/15 text-emerald-300 border-emerald-500/30";
    case TrustLevel.LOW_RISK:
      return "bg-sky-500/15 text-sky-300 border-sky-500/30";
    case TrustLevel.MEDIUM_RISK:
      return "bg-amber-500/15 text-amber-300 border-amber-500/30";
    case TrustLevel.HIGH_RISK:
      return "bg-orange-500/15 text-orange-300 border-orange-500/30";
    case TrustLevel.CRITICAL:
      return "bg-rose-500/15 text-rose-300 border-rose-500/30";
    default:
      return "bg-slate-500/15 text-slate-300 border-slate-500/30";
  }
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
