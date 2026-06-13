import { describe, expect, it } from "vitest";
import { Code, ConnectError } from "@connectrpc/connect";
import { isUnavailableError, retryUnlessUnavailable } from "./availability";

describe("isUnavailableError", () => {
  it("is true for UNIMPLEMENTED and UNAVAILABLE Connect errors", () => {
    expect(
      isUnavailableError(new ConnectError("nope", Code.Unimplemented)),
    ).toBe(true);
    expect(isUnavailableError(new ConnectError("nope", Code.Unavailable))).toBe(
      true,
    );
  });

  it("is false for other Connect errors and plain errors", () => {
    expect(
      isUnavailableError(new ConnectError("boom", Code.Internal)),
    ).toBe(false);
    expect(isUnavailableError(new Error("boom"))).toBe(false);
    expect(isUnavailableError("boom")).toBe(false);
  });
});

describe("retryUnlessUnavailable", () => {
  it("never retries an unavailable error", () => {
    const err = new ConnectError("nope", Code.Unimplemented);
    expect(retryUnlessUnavailable(0, err)).toBe(false);
  });

  it("retries other errors once", () => {
    const err = new ConnectError("boom", Code.Internal);
    expect(retryUnlessUnavailable(0, err)).toBe(true);
    expect(retryUnlessUnavailable(1, err)).toBe(false);
  });
});
