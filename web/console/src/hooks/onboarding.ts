import { useCallback, useEffect, useState } from "react";
import { useSession } from "../state/useAuth";
import {
  useActivePolicy,
  useTenantOverview,
  useTrustSessionStats,
} from "./queries";
import { useVerifyAuditChain } from "./compliance";
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
  const overview = useTenantOverview();
  const trust = useTrustSessionStats();
  const tenantPolicy = useActivePolicy("");
  const chain = useVerifyAuditChain();

  const [dismissed, setDismissed] = useState(() => readDismissed(tenantId));

  // Re-read the persisted preference if the tenant changes (login switch).
  useEffect(() => {
    setDismissed(readDismissed(tenantId));
  }, [tenantId]);

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
  const hasPolicy = tenantPolicy.data != null;
  const auditEntries = chain.data?.verifiedCount ?? 0n;

  const steps: OnboardingStep[] = [
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
      done: auditEntries > 0n,
    },
  ];

  const completedCount = steps.filter((s) => s.done).length;
  const loading =
    overview.isLoading ||
    trust.isLoading ||
    tenantPolicy.isLoading ||
    chain.isLoading;

  return {
    steps,
    completedCount,
    total: steps.length,
    allDone: completedCount === steps.length,
    loading,
    dismissed,
    dismiss: () => persist(true),
    resume: () => persist(false),
  };
}
