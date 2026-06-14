import { docsBaseUrl } from "../config";

// Resolves a documentation deep-link from the (deploy-time configurable) docs
// base. Used by onboarding and inline help so every "learn more" link points at
// the same, overridable source of truth.
export function docLink(path: string): string {
  const base = docsBaseUrl();
  const clean = path.replace(/^\/+/, "");
  return clean ? `${base}/${clean}` : base;
}

// Named docs referenced by the console. Keeping them centralized means a doc
// rename only changes one place.
export const docs = {
  quickstart: () => docLink("cli.md"),
  sdkAndroid: () => docLink("build-hardening-android.md"),
  sdkIos: () => docLink("build-hardening-ios.md"),
  policyPacks: () => docLink("policy-packs.md"),
  auditTrail: () => docLink("audit-trail.md"),
  killSwitch: () => docLink("kill-switch.md"),
  canary: () => docLink("canary-rollout.md"),
  dataSafety: () => docLink("data-safety.md"),
  masvs: () => docLink("masvs-evidence.md"),
  siem: () => docLink("siem-integration.md"),
};
