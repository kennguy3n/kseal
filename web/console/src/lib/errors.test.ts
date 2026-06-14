import { describe, expect, it } from "vitest";
import { Code, ConnectError } from "@connectrpc/connect";
import { errorMessage, isConnectionError } from "./errors";

describe("errorMessage", () => {
  it("uses a ConnectError's rawMessage (no numeric code prefix)", () => {
    expect(errorMessage(new ConnectError("boom", Code.Internal))).toBe("boom");
  });

  it("falls back to Error.message and String() for other values", () => {
    expect(errorMessage(new Error("plain"))).toBe("plain");
    expect(errorMessage("weird")).toBe("weird");
  });
});

describe("isConnectionError", () => {
  it("is true for a fetch TypeError thrown by the browser", () => {
    expect(isConnectionError(new TypeError("Failed to fetch"))).toBe(true);
    expect(
      isConnectionError(
        new TypeError("NetworkError when attempting to fetch resource."),
      ),
    ).toBe(true);
    expect(isConnectionError(new TypeError("Load failed"))).toBe(true);
  });

  it("is true when connect-web wraps the fetch failure as code Unknown", () => {
    // connect-web rejects with ConnectError.from(typeError): code Unknown,
    // message carried through, original TypeError kept as `cause`.
    const wrapped = new ConnectError(
      "Failed to fetch",
      Code.Unknown,
      undefined,
      undefined,
      new TypeError("Failed to fetch"),
    );
    expect(isConnectionError(wrapped)).toBe(true);

    // Even without a TypeError cause, the network-failure message is enough.
    expect(
      isConnectionError(new ConnectError("Load failed", Code.Unknown)),
    ).toBe(true);
  });

  it("is false for a real coded server response", () => {
    expect(
      isConnectionError(new ConnectError("denied", Code.PermissionDenied)),
    ).toBe(false);
    // Unavailable/Unimplemented are handled by isUnavailableError, not here.
    expect(
      isConnectionError(new ConnectError("nope", Code.Unavailable)),
    ).toBe(false);
  });

  it("is false for a non-network Unknown error and plain values", () => {
    expect(isConnectionError(new ConnectError("boom", Code.Unknown))).toBe(
      false,
    );
    expect(isConnectionError(new Error("Failed to fetch"))).toBe(false);
    expect(isConnectionError("Failed to fetch")).toBe(false);
  });
});
