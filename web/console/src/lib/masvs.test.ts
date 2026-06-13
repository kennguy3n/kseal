import { describe, expect, it } from "vitest";
import { create } from "@bufbuild/protobuf";
import { BuildSchema } from "../gen/kseal/v1/registry_pb";
import { buildMasvsReport, MASVS_CATEGORIES } from "./masvs";

function build(manifest: string) {
  return create(BuildSchema, {
    id: "build-1",
    appId: "app-1",
    buildHash: "deadbeefcafef00d",
    versionName: "4.2.0",
    versionCode: 420n,
    manifest,
  });
}

describe("buildMasvsReport", () => {
  it("maps manifest modules onto MASVS categories", () => {
    const rep = buildMasvsReport(
      build(
        JSON.stringify({
          modules: ["root", "attestation"],
          modules_enabled: ["crypto"],
          transforms: ["string-obfuscation", "symbol-strip"],
        }),
      ),
    );

    expect(rep.totalCategories).toBe(MASVS_CATEGORIES.length);
    // root -> PLATFORM, RESILIENCE; attestation -> AUTH, NETWORK; crypto -> CRYPTO
    const covered = rep.categories
      .filter((c) => c.covered)
      .map((c) => c.category)
      .sort();
    expect(covered).toEqual(
      ["AUTH", "CRYPTO", "NETWORK", "PLATFORM", "RESILIENCE"].sort(),
    );
    expect(rep.coveredCount).toBe(5);
    expect(rep.gaps).toEqual(expect.arrayContaining(["STORAGE", "CODE"]));
    // modules are deduped + sorted across both manifest keys.
    expect(rep.modules).toEqual(["attestation", "crypto", "root"]);
    expect(rep.transforms).toEqual(["string-obfuscation", "symbol-strip"]);
  });

  it("normalizes module naming variants", () => {
    const rep = buildMasvsReport(
      build(JSON.stringify({ modules: ["anti-hooking", "App_Integrity"] })),
    );
    const resilience = rep.categories.find((c) => c.category === "RESILIENCE");
    expect(resilience?.covered).toBe(true);
    // anti-hooking + appintegrity both contribute to RESILIENCE.
    expect(resilience?.modules).toEqual(["App_Integrity", "anti-hooking"]);
  });

  it("records a note for an empty manifest but still returns the build proof", () => {
    const rep = buildMasvsReport(build(""));
    expect(rep.buildHash).toBe("deadbeefcafef00d");
    expect(rep.coveredCount).toBe(0);
    expect(rep.notes.some((n) => n.includes("manifest is empty"))).toBe(true);
  });

  it("records a note for invalid JSON without throwing", () => {
    const rep = buildMasvsReport(build("{not json"));
    expect(rep.modules).toEqual([]);
    expect(rep.notes.some((n) => n.includes("not valid JSON"))).toBe(true);
  });

  it("flags unmapped modules in notes", () => {
    const rep = buildMasvsReport(
      build(JSON.stringify({ modules: ["totally-unknown"] })),
    );
    expect(
      rep.notes.some((n) => n.includes('"totally-unknown" is not mapped')),
    ).toBe(true);
  });

  it("ignores non-string manifest array entries defensively", () => {
    const rep = buildMasvsReport(
      build(JSON.stringify({ modules: ["crypto", 42, null] })),
    );
    expect(rep.modules).toEqual(["crypto"]);
  });
});
