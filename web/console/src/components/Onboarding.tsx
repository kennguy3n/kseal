import { useId } from "react";
import { Link } from "react-router-dom";
import { useOnboarding, type OnboardingStep } from "../hooks/onboarding";
import {
  ArrowRightIcon,
  CheckIcon,
  CloseIcon,
  ShieldIcon,
} from "./icons";
import { Skeleton } from "./ui";

function ProgressBar({ value, max }: { value: number; max: number }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div
      className="h-1.5 w-full overflow-hidden rounded-full bg-elevated"
      role="progressbar"
      aria-valuenow={value}
      aria-valuemin={0}
      aria-valuemax={max}
      aria-label={`${value} of ${max} steps complete`}
    >
      <div
        className="h-full rounded-full bg-accent-strong transition-all"
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

function StepRow({ step, index }: { step: OnboardingStep; index: number }) {
  return (
    <li className="flex gap-3 py-3">
      <span
        className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-xs font-semibold ${
          step.done
            ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
            : "border-line-strong text-fg-muted"
        }`}
      >
        {step.done ? (
          <>
            <CheckIcon className="h-3.5 w-3.5" />
            <span className="sr-only">Completed:</span>
          </>
        ) : (
          <>
            <span aria-hidden="true">{index + 1}</span>
            <span className="sr-only">To do:</span>
          </>
        )}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span
            className={`text-sm font-medium ${
              step.done ? "text-fg-muted line-through" : "text-fg-strong"
            }`}
          >
            {step.title}
          </span>
          {step.done && (
            <span className="text-xs font-medium text-emerald-700 dark:text-emerald-300">
              Done
            </span>
          )}
        </div>
        <p className="mt-1 text-xs text-fg-muted">{step.why}</p>
        {!step.done && (
          <div className="mt-2 flex flex-wrap items-center gap-3">
            <Link
              to={step.to}
              className="inline-flex items-center gap-1 text-xs font-medium text-accent hover:underline"
            >
              {step.actionLabel}
              <ArrowRightIcon className="h-3.5 w-3.5" />
            </Link>
            {step.docHref && (
              <a
                href={step.docHref}
                target="_blank"
                rel="noreferrer"
                className="text-xs text-fg-muted hover:text-fg hover:underline"
              >
                Read the guide
              </a>
            )}
          </div>
        )}
      </div>
    </li>
  );
}

export function Onboarding() {
  const {
    steps,
    completedCount,
    total,
    allDone,
    loading,
    error,
    dismissed,
    dismiss,
    resume,
  } = useOnboarding();
  const headingId = useId();

  // Dismissed users never see the loading skeleton for a section they
  // explicitly closed. Render nothing while data is still loading (so a stale
  // "0 of N" never flashes), when everything is done (nothing to resume), or
  // when the state is untrustworthy because every query failed with no progress
  // detected (the `error` flag). A genuine zero-progress state (queries
  // succeeded, nothing done yet) is NOT hidden — those users most need the
  // resume nudge, otherwise a developer who dismisses before completing a step
  // could never get the checklist back without clearing localStorage.
  if (dismissed) {
    if (loading || allDone || (error && completedCount === 0)) return null;
    return (
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-surface px-4 py-3">
        <div className="flex items-center gap-2 text-sm text-fg">
          <ShieldIcon className="h-4 w-4 text-accent" />
          <span>
            Finish securing your app —{" "}
            <span className="font-medium text-fg-strong">
              {completedCount} of {total}
            </span>{" "}
            steps done.
          </span>
        </div>
        <button type="button" className="btn-ghost" onClick={resume}>
          Resume setup
        </button>
      </div>
    );
  }

  // Non-dismissed first load (no data yet): show a lightweight placeholder so
  // the checklist doesn't pop in after the dashboard renders. We also hold the
  // placeholder when every signal failed with no progress detected, so a
  // transient outage never renders a misleading "0 of N" to a user who may
  // actually have progress; React Query refetches and resolves it on recovery.
  if ((loading || error) && completedCount === 0) {
    return (
      <section className="card" aria-busy="true">
        <Skeleton className="h-4 w-40" />
        <Skeleton className="mt-3 h-1.5 w-full" />
        <div className="mt-4 space-y-3">
          <Skeleton className="h-3 w-2/3" />
          <Skeleton className="h-3 w-1/2" />
        </div>
      </section>
    );
  }

  return (
    <section
      className="card border-accent-strong/30"
      aria-labelledby={headingId}
    >
      <header className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-accent-strong/15 text-accent">
            <ShieldIcon className="h-5 w-5" />
          </span>
          <div>
            <h2
              id={headingId}
              className="text-base font-semibold text-fg-strong"
            >
              {allDone ? "Your app is protected" : "Secure your app"}
            </h2>
            <p className="mt-1 text-sm leading-relaxed text-fg-muted">
              {allDone
                ? "Every setup step is complete. You can revisit these areas any time from the sidebar."
                : "A guided path from registering an app to live protection. Each step explains why it matters."}
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={dismiss}
          aria-label="Dismiss onboarding checklist"
          className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-fg-muted hover:bg-elevated hover:text-fg"
        >
          <CloseIcon className="h-4 w-4" />
        </button>
      </header>

      <div className="mt-4 flex items-center gap-3">
        <ProgressBar value={completedCount} max={total} />
        <span className="shrink-0 text-xs font-medium text-fg-muted">
          {completedCount}/{total}
        </span>
      </div>

      {allDone ? (
        <div className="mt-4 flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-700 dark:text-emerald-300">
          <CheckIcon className="h-4 w-4" />
          All {total} steps complete — protection is live.
        </div>
      ) : (
        <ol className="mt-2 divide-y divide-line">
          {steps.map((step, i) => (
            <StepRow key={step.id} step={step} index={i} />
          ))}
        </ol>
      )}
    </section>
  );
}
