import { Code, ConnectError } from "@connectrpc/connect";

// Extracts a human-readable message from a Connect/JS error. ConnectError's
// rawMessage omits the numeric code prefix that `.message` includes, keeping
// surfaced copy clean for end users.
export function errorMessage(error: unknown): string {
  if (error instanceof ConnectError) return error.rawMessage;
  if (error instanceof Error) return error.message;
  return String(error);
}

// Browser fetch network-failure messages. The wording differs per engine:
// Chromium "Failed to fetch", Firefox "NetworkError when attempting to fetch
// resource.", Safari "Load failed". undici (Node) uses "fetch failed".
const NETWORK_FAILURE_MESSAGE =
  /failed to fetch|networkerror|load failed|fetch failed/i;

// True when an error means the request never got a response from the server:
// it was unreachable, refused the connection, or the browser blocked it (e.g.
// a cross-origin call the server's CORS allowlist doesn't permit). The browser
// throws a TypeError; connect-web wraps it as a ConnectError with code
// "unknown" carrying that message (its `cause` is the original TypeError).
//
// This is deliberately disjoint from isUnavailableError (Unimplemented/
// Unavailable = the server responded that a capability isn't deployed): a
// connection failure never reaches the server, so it must be surfaced as a
// "can't reach the API" condition rather than a generic or "not deployed" one.
export function isConnectionError(error: unknown): boolean {
  if (error instanceof ConnectError) {
    if (error.code !== Code.Unknown) return false;
    if (error.cause instanceof TypeError) return true;
    return NETWORK_FAILURE_MESSAGE.test(error.rawMessage);
  }
  if (error instanceof TypeError) {
    return NETWORK_FAILURE_MESSAGE.test(error.message);
  }
  return false;
}
