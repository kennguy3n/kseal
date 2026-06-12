import { EnforcementMode } from "../gen/kseal/v1/common_pb";

// Form <-> CreatePolicyRequest transformation and validation, kept pure so the
// Policy editor's logic is unit-testable without rendering.
export interface PolicyFormState {
  name: string;
  appId: string;
  enforcementMode: EnforcementMode;
  // Free-form: modules separated by comma, whitespace, or newlines.
  modulesText: string;
  // JSON objects edited as text in the UI.
  riskThresholdsJson: string;
  rulesJson: string;
}

export interface PolicyDraft {
  name: string;
  appId: string;
  enforcementMode: EnforcementMode;
  modulesEnabled: string[];
  // Canonical JSON strings sent to the server (matches proto string fields).
  riskThresholds: string;
  rules: string;
}

export type PolicyValidation =
  | { ok: true; draft: PolicyDraft }
  | { ok: false; errors: Partial<Record<keyof PolicyFormState, string>> };

export function parseModules(text: string): string[] {
  return Array.from(
    new Set(
      text
        .split(/[\s,]+/)
        .map((m) => m.trim())
        .filter((m) => m.length > 0),
    ),
  );
}

// Validates that the text is a JSON object (not array/primitive) and returns
// its canonical (key-stable) serialization for storage.
function parseJsonObject(
  text: string,
): { ok: true; canonical: string } | { ok: false; error: string } {
  const trimmed = text.trim();
  if (trimmed === "") return { ok: true, canonical: "{}" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch (err) {
    return { ok: false, error: `Invalid JSON: ${(err as Error).message}` };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, error: "Expected a JSON object" };
  }
  return { ok: true, canonical: JSON.stringify(parsed) };
}

export function parsePolicyForm(state: PolicyFormState): PolicyValidation {
  const errors: Partial<Record<keyof PolicyFormState, string>> = {};

  const name = state.name.trim();
  if (name === "") errors.name = "Name is required";

  if (state.enforcementMode === EnforcementMode.UNSPECIFIED) {
    errors.enforcementMode = "Choose an enforcement mode";
  }

  const thresholds = parseJsonObject(state.riskThresholdsJson);
  if (!thresholds.ok) errors.riskThresholdsJson = thresholds.error;

  const rules = parseJsonObject(state.rulesJson);
  if (!rules.ok) errors.rulesJson = rules.error;

  if (Object.keys(errors).length > 0) return { ok: false, errors };

  return {
    ok: true,
    draft: {
      name,
      appId: state.appId.trim(),
      enforcementMode: state.enforcementMode,
      modulesEnabled: parseModules(state.modulesText),
      riskThresholds: (thresholds as { canonical: string }).canonical,
      rules: (rules as { canonical: string }).canonical,
    },
  };
}

export const enforcementModeOptions: { value: EnforcementMode; label: string }[] = [
  { value: EnforcementMode.OBSERVE, label: "Observe" },
  { value: EnforcementMode.STEP_UP, label: "Step-up" },
  { value: EnforcementMode.BLOCK, label: "Block" },
];
