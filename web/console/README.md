# web/console

React admin console / dashboard.

The self-service web UI for the [control plane](../../server/control-plane). Provides:

- Tenant / app / build management and SDK onboarding
- Test-mode risk events and runtime threat dashboards
- Policy authoring + the [policy simulator](../../PROPOSAL.md#noops-product-experience) (replay traffic against candidate policy)
- Canary rollout, kill switch, and false-positive guardrails
- MASVS evidence reports, privacy disclosure artifacts, and audit views
- SIEM/webhook configuration and billing/usage views

**Stack:** React + TypeScript. **Status:** scaffold — see [PROGRESS.md](../../PROGRESS.md) (Phase 1+).
