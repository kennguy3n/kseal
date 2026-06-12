# tests

Integration and end-to-end tests.

Cross-cutting tests that span multiple components (unit tests live alongside their source). Expected coverage:

- **Trust session E2E** — challenge → platform attestation → trust token → signed request proof → server decision.
- **Attestation verification** — Play Integrity / App Attest / DeviceCheck verifier behavior.
- **SDK performance** — assert the [performance budgets](../ARCHITECTURE.md#performance-budgets) (startup, memory, binary size) as CI gates.
- **Policy simulation** — replay fixtures against candidate policies and assert observe/step-up/block outcomes.
- **Privacy contract** — assert telemetry contains no disallowed fields and matches the machine-readable data contract.
- **Tenant isolation** — assert no cross-tenant read paths.

**Status:** scaffold — see [PROGRESS.md](../PROGRESS.md).
