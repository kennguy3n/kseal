import { useCallback, useEffect, useMemo, useState } from "react";
import { useSession } from "../state/useAuth";
import {
  usePolicies,
  useTenantOverview,
  useTrustSessionStats,
} from "./queries";
import { useHasAuditActivity } from "./compliance";
import { docs } from "../lib/links";

export interface OnboardingStep {
  id: string;
  title: string;
  // Short "why this matters" rationale shown under each step.
  why: string;
  // Internal route this step points at (the primary call-to-action).
  to: string;
  actionLabel: string;
  // Optional external documentation deep-link ("Read the guide").
  docHref?: string;
  done: boolean;
}

export interface OnboardingState {
  steps: OnboardingStep[];
  completedCount: number;
  total: number;
  allDone: boolean;
  loading: boolean;
  // True when the derived state can't be trusted because every underlying query
  // failed (vs. legitimately returning "nothing done yet"). Lets the view avoid
  // showing a misleading "0 of N" to someone who may actually have progress.
  error: boolean;
  dismissed: boolean;
  dismiss: () => void;
  resume: () => void;
}

function storageKey(tenantId: string): string {
  return `kseal.console.onboarding.${tenantId}`;
}

function readDismissed(tenantId: string): boolean {
  try {
    const raw = localStorage.getItem(storageKey(tenantId));
    if (!raw) return false;
    return JSON.parse(raw)?.dismissed === true;
  } catch {
    return false;
  }
}

// Drives the guided "Secure your app" onboarding. Step completion is derived
// from live tenant data (never a local checkbox) so the checklist always
// reflects reality and resumes correctly across sessions and devices. The
// dismissed/expanded preference is the only thing persisted locally.
export function useOnboarding(): OnboardingState {
  const { tenantId } = useSession();

  const [dismissed, setDismissed] = useState(() => readDismissed(tenantId));

  // Re-read the persisted preference if the tenant changes (login switch).
  useEffect(() => {
    setDismissed(readDismissed(tenantId));
  }, [tenantId]);

  const overview = useTenantOverview();
  const trust = useTrustSessionStats();
  // List every policy for the tenant (appId "" returns all scopes) so the
  // "turn on a policy" step is satisfied by any active policy — tenant-wide OR
  // app-scoped. GetActivePolicy("") would only match tenant-wide rows and miss
  // a developer who only activated an app-scoped policy.
  const policies = usePolicies("");
  // "Has audit activity" is derived from a cheap single-row probe, not the
  // expensive hash-chain verification, so rendering onboarding on the dashboard
  // never triggers a full chain recompute.
  const audit = useHasAuditActivity();

  const persist = useCallback(
    (value: boolean) => {
      setDismissed(value);
      try {
        localStorage.setItem(
          storageKey(tenantId),
          JSON.stringify({ dismissed: value }),
        );
      } catch {
        /* ignore persistence failures */
      }
    },
    [tenantId],
  );

  const appCount = overview.data?.appCount ?? 0;
  const tokensIssued = trust.data?.tokensIssued ?? 0n;
  const totalSessions = trust.data?.totalSessions ?? 0n;
  const hasPolicy = (policies.data ?? []).some((p) => p.isActive);
  const hasAuditActivity = audit.data ?? false;

  const steps: OnboardingStep[] = useMemo(
    () => [
      {
        id: "register-app",
        title: "Register your first app",
        why: "Apps are the unit kseal protects. Registering one gives you the app ID and signing keys the SDK and CLI bind to.",
        to: "/apps",
        actionLabel: "Go to Apps",
        docHref: docs.quickstart(),
        done: appCount > 0,
      },
      {
        id: "integrate-sdk",
        title: "Integrate the kseal SDK",
        why: "The SDK adds runtime protection (RASP) and attests each device, so your backend can trust the app it is talking to.",
        to: "/apps",
        actionLabel: "Open quickstart",
        docHref: docs.sdkAndroid(),
        done: tokensIssued > 0n,
      },
      {
        id: "trust-session",
        title: "Confirm your first trust session",
        why: "A trust session proves a real device passed attestation. Seeing one means your integration is live end-to-end.",
        to: "/",
        actionLabel: "View trust sessions",
        done: totalSessions > 0n,
      },
      {
        id: "turn-on-policy",
        title: "Turn on a protection policy",
        why: "Policies decide how risk is enforced (observe, step-up or block). Activating one moves you from monitoring to protection.",
        to: "/policies",
        actionLabel: "Author a policy",
        docHref: docs.policyPacks(),
        done: hasPolicy,
      },
      {
        id: "explore-operations",
        title: "Review audit, kill switch & canary",
        why: "Tamper-evident audit, a signed kill switch and staged canary rollouts are how you operate and prove compliance day to day.",
        to: "/audit",
        actionLabel: "Open audit trail",
        docHref: docs.auditTrail(),
        done: hasAuditActivity,
      },
    ],
    [appCount, tokensIssued, totalSessions, hasPolicy, hasAuditActivity],
  );

  const completedCount = steps.filter((s) => s.done).length;
  const loading =
    overview.isLoading ||
    trust.isLoading ||
    policies.isLoading ||
    audit.isLoading;
  // Only treat it as an "untrustworthy" error when every signal failed; a
  // partial failure still yields a meaningful (if conservative) completion
  // count, so we let that render normally.
  const error =
    overview.isError &&
    trust.isError &&
    policies.isError &&
    audit.isError;

  return {
    steps,
    completedCount,
    total: steps.length,
    allDone: completedCount === steps.length,
    loading,
    error,
    dismissed,
    dismiss: () => persist(true),
    resume: () => persist(false),
  };
}
