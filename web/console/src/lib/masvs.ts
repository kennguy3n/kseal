import type { Build } from "../gen/kseal/v1/registry_pb";

// MASVS evidence, computed client-side from a registered build's manifest — the
// same derivation the CLI report generator does (cmd/kseal-cli masvs.go) so the
// console and the CLI agree without a server round-trip. The build proof and
// module/transform provenance come straight from RegistryService builds, which
// the console already reads, so this view is real data today (no dependency on
// the WS-K RPCs).

// Ordered MASVS categories, mirroring docs/masvs-mapping.md.
export const MASVS_CATEGORIES = [
  "STORAGE",
  "CRYPTO",
  "AUTH",
  "NETWORK",
  "PLATFORM",
  "CODE",
  "RESILIENCE",
  "PRIVACY",
] as const;

export type MasvsCategory = (typeof MASVS_CATEGORIES)[number];

// Maps a hardening/RASP module to the MASVS categories it evidences. Keys are
// normalized (lower-case, non-alphanumeric stripped) so manifest naming
// variants ("anti-hooking", "anti_hooking", "antiHooking") all resolve. Mirrors
// moduleMASVS in cmd/kseal-cli/internal/cli/masvs.go.
const MODULE_MASVS: Record<string, MasvsCategory[]> = {
  integrity: ["CODE", "RESILIENCE"],
  appintegrity: ["CODE", "RESILIENCE"],
  rasp: ["PLATFORM", "RESILIENCE"],
  attestation: ["AUTH", "NETWORK"],
  apiattestation: ["AUTH", "NETWORK"],
  network: ["NETWORK"],
  tls: ["NETWORK"],
  obfuscation: ["CODE", "RESILIENCE"],
  antihooking: ["RESILIENCE"],
  hooking: ["RESILIENCE"],
  environment: ["PLATFORM", "RESILIENCE"],
  root: ["PLATFORM", "RESILIENCE"],
  jailbreak: ["PLATFORM", "RESILIENCE"],
  storage: ["STORAGE"],
  crypto: ["CRYPTO"],
  privacy: ["PRIVACY"],
};

export interface MasvsCategoryCoverage {
  category: MasvsCategory;
  covered: boolean;
  modules: string[];
}

export interface MasvsReport {
  buildId: string;
  appId: string;
  buildHash: string;
  versionName: string;
  versionCode: number;
  modules: string[];
  transforms: string[];
  categories: MasvsCategoryCoverage[];
  coveredCount: number;
  totalCategories: number;
  gaps: MasvsCategory[];
  notes: string[];
}

interface ManifestProvenance {
  modules?: unknown;
  modules_enabled?: unknown;
  transforms?: unknown;
}

function normalizeModule(s: string): string {
  let out = "";
  for (const ch of s.toLowerCase()) {
    if ((ch >= "a" && ch <= "z") || (ch >= "0" && ch <= "9")) out += ch;
  }
  return out;
}

function dedupeSorted(values: string[]): string[] {
  const seen = new Set<string>();
  for (const raw of values) {
    const s = raw.trim();
    if (s) seen.add(s);
  }
  return [...seen].sort();
}

// Defensive: a manifest field may be absent or the wrong type. Coerce only
// genuine string arrays; anything else contributes nothing.
function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === "string");
}

// Derives a MASVS evidence report from a registered build. A missing or
// unparseable manifest is not an error: the report still renders the build
// proof and records the absence as a note, so the view is always informative.
export function buildMasvsReport(build: Build): MasvsReport {
  const notes: string[] = [];
  let modules: string[] = [];
  let transforms: string[] = [];

  const manifest = build.manifest.trim();
  if (manifest === "") {
    notes.push(
      "build manifest is empty: no module provenance to map; only the build-hash proof is available",
    );
  } else {
    try {
      const prov = JSON.parse(manifest) as ManifestProvenance;
      modules = dedupeSorted([
        ...asStringArray(prov.modules),
        ...asStringArray(prov.modules_enabled),
      ]);
      transforms = dedupeSorted(asStringArray(prov.transforms));
    } catch {
      notes.push(
        "build manifest is not valid JSON: module coverage could not be derived",
      );
    }
  }

  const byCategory: Record<MasvsCategory, Set<string>> = {
    STORAGE: new Set(),
    CRYPTO: new Set(),
    AUTH: new Set(),
    NETWORK: new Set(),
    PLATFORM: new Set(),
    CODE: new Set(),
    RESILIENCE: new Set(),
    PRIVACY: new Set(),
  };

  for (const m of modules) {
    const cats = MODULE_MASVS[normalizeModule(m)];
    if (!cats) {
      notes.push(`module "${m}" is not mapped to a MASVS category`);
      continue;
    }
    for (const cat of cats) byCategory[cat].add(m);
  }

  const categories: MasvsCategoryCoverage[] = [];
  const gaps: MasvsCategory[] = [];
  let coveredCount = 0;
  for (const cat of MASVS_CATEGORIES) {
    const mods = [...byCategory[cat]].sort();
    const covered = mods.length > 0;
    categories.push({ category: cat, covered, modules: mods });
    if (covered) coveredCount++;
    else gaps.push(cat);
  }

  notes.push(
    "evidence is derived from the registered build-manifest module set and the build-hash proof; the registry/query RPCs do not expose per-control MASTG verification status or signed attestation artifacts",
  );

  return {
    buildId: build.id,
    appId: build.appId,
    buildHash: build.buildHash,
    versionName: build.versionName,
    versionCode: Number(build.versionCode),
    modules,
    transforms,
    categories,
    coveredCount,
    totalCategories: MASVS_CATEGORIES.length,
    gaps,
    notes,
  };
}
