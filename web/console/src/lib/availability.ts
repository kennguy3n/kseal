import { Code, ConnectError } from "@connectrpc/connect";

// The console-local compliance/ops RPCs (audit trail, data-processing registry,
// kill switch, canary monitor) are being added to the canonical server by
// WS-K. Until they are deployed, a server returns UNIMPLEMENTED (no handler) or
// UNAVAILABLE (route not wired). We treat both as "capability not deployed yet"
// and render a clean degraded state rather than a hard error — exactly the
// graceful-degradation contract the console-local client exists for.
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
