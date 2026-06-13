import { Code, ConnectError } from "@connectrpc/connect";

// The compliance/ops views (audit trail, data-processing registry, kill switch,
// canary monitor) read the canonical ComplianceService. A server build that
// predates that service (or has the compliance routes unwired) returns
// UNIMPLEMENTED (no handler) or UNAVAILABLE (route not reachable). We treat both
// as "capability not deployed yet" and render a clean degraded state rather than
// a hard error.
export function isUnavailableError(error: unknown): boolean {
  if (!(error instanceof ConnectError)) return false;
  return error.code === Code.Unimplemented || error.code === Code.Unavailable;
}

// react-query retry predicate: never retry a "not deployed yet" error (it will
// not succeed on retry and only delays showing the degraded state), but allow a
// single retry for other transient failures.
export function retryUnlessUnavailable(failureCount: number, error: unknown): boolean {
  if (isUnavailableError(error)) return false;
  return failureCount < 1;
}
