import { describe, expect, it } from "vitest";
import type {
  UnaryRequest,
  UnaryResponse,
  StreamRequest,
  StreamResponse,
} from "@connectrpc/connect";
import { authInterceptor } from "./transport";

// Minimal request stub: the interceptor only touches `header`.
function fakeRequest(): UnaryRequest {
  return { header: new Headers() } as unknown as UnaryRequest;
}

const echoNext = async (
  req: UnaryRequest | StreamRequest,
): Promise<UnaryResponse | StreamResponse> =>
  ({ header: req.header }) as unknown as UnaryResponse;

async function runInterceptor(apiKey: string | null): Promise<Headers> {
  const interceptor = authInterceptor(() => apiKey);
  const captured = fakeRequest();
  await interceptor(echoNext)(captured);
  return captured.header;
}

describe("authInterceptor", () => {
  it("attaches a bearer Authorization header when a key is present", async () => {
    const header = await runInterceptor("ksk_secret");
    expect(header.get("Authorization")).toBe("Bearer ksk_secret");
  });

  it("does not set the header when no key is available", async () => {
    const header = await runInterceptor(null);
    expect(header.has("Authorization")).toBe(false);
  });

  it("reads the key lazily on each call", async () => {
    let key = "first";
    const interceptor = authInterceptor(() => key);

    const r1 = fakeRequest();
    await interceptor(echoNext)(r1);
    expect(r1.header.get("Authorization")).toBe("Bearer first");

    key = "second";
    const r2 = fakeRequest();
    await interceptor(echoNext)(r2);
    expect(r2.header.get("Authorization")).toBe("Bearer second");
  });
});
