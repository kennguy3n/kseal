import { ConnectError } from "@connectrpc/connect";

// Extracts a human-readable message from a Connect/JS error. ConnectError's
// rawMessage omits the numeric code prefix that `.message` includes, keeping
// surfaced copy clean for end users.
export function errorMessage(error: unknown): string {
  if (error instanceof ConnectError) return error.rawMessage;
  if (error instanceof Error) return error.message;
  return String(error);
}
