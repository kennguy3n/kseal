package buildproof

import "testing"

const androidJSON = `{
  "schema": "kseal.build-proof/v1",
  "platform": "android",
  "build_hash": "abc123def456abc123def456abc123def456abc123def456abc123def4560000",
  "app": {"package_id": "com.example.app", "version_name": "2.0", "version_code": 7},
  "sdk": {"name": "kseal-android", "version": "0.1.0"},
  "seed": {"digest": "deadbeef", "algorithm": "HKDF-SHA256", "derivation": "content"},
  "tooling": {"gradle": "8.11.1", "r8_mapping": true},
  "transforms": [
    {"name": "native-library-harden", "status": "applied", "details": {"library_count": 2, "summary": {"cfi_enabled": 1, "cfi_unsupported": 1}}},
    {"name": "string-resource-seal", "status": "applied", "details": {"count": 9}},
    {"name": "polymorphism", "status": "applied", "details": {"algorithm": "HKDF-SHA256"}}
  ],
  "artifacts": [{"path": "a", "sha256": "1"}, {"path": "b", "sha256": "2"}]
}`

const iosJSON = `{
  "schemaVersion": "1.0",
  "platform": "ios",
  "sdkVersion": "0.1.0",
  "buildHash": "feedface00000000000000000000000000000000000000000000000000000000",
  "versionName": "2.0",
  "versionCode": 7,
  "polymorphism": {"seedDigest": "cafef00d", "algorithm": "sha256-ctr"},
  "toolVersions": {"swift": "5.10"},
  "transforms": [
    {"kind": "string-obfuscation", "algorithm": "seed-xor/sha256-ctr", "count": 3},
    {"kind": "macho-section-integrity", "algorithm": "sha256", "count": 5, "detail": {"slices": "1", "format": "macho"}}
  ],
  "modules": ["string-hardening", "polymorphism", "build-proof", "macho-section-integrity"],
  "integrity": {"format": "macho", "slices": [
    {"arch": "arm64", "fileType": "execute", "pie": true, "encrypted": false, "sections": [{"hash": "x"}, {"hash": ""}]}
  ]}
}`

func TestParseAndroid(t *testing.T) {
	m, err := Parse([]byte(androidJSON))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.Platform != "android" || m.AppID != "com.example.app" || m.VersionCode != 7 {
		t.Errorf("unexpected identity: %+v", m)
	}
	if m.SeedDigest != "deadbeef" || m.SDKVersion != "0.1.0" {
		t.Errorf("unexpected seed/sdk: %+v", m)
	}
	if m.ArtifactCount != 2 {
		t.Errorf("artifact count = %d, want 2", m.ArtifactCount)
	}
	nat, ok := m.Transform("native-library-harden")
	if !ok || !nat.Applied() || nat.Count != 2 {
		t.Fatalf("native transform = %+v ok=%v", nat, ok)
	}
	summary := nat.Detail["summary"].(map[string]any)
	if summary["cfi_enabled"].(float64) != 1 {
		t.Errorf("cfi_enabled = %v, want 1", summary["cfi_enabled"])
	}
	if !m.HasAppliedTransform("polymorphism") {
		t.Errorf("expected polymorphism applied")
	}
	// Android transform names double as module identifiers.
	if got := len(m.Modules); got != 3 {
		t.Errorf("modules = %v", m.Modules)
	}
}

func TestParseIOS(t *testing.T) {
	m, err := Parse([]byte(iosJSON))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.Platform != "ios" || m.Schema != "ios:1.0" || m.SeedDigest != "cafef00d" {
		t.Errorf("unexpected identity: %+v", m)
	}
	so, ok := m.Transform("string-obfuscation")
	if !ok || so.Count != 3 || so.Detail["algorithm"] != "seed-xor/sha256-ctr" {
		t.Errorf("string-obfuscation = %+v ok=%v", so, ok)
	}
	if m.Integrity == nil || len(m.Integrity.Slices) != 1 {
		t.Fatalf("integrity = %+v", m.Integrity)
	}
	s := m.Integrity.Slices[0]
	if s.Arch != "arm64" || !s.PIE || s.SectionCount != 2 {
		t.Errorf("slice = %+v", s)
	}
}

func TestParseRejectsUnknownSchema(t *testing.T) {
	if _, err := Parse([]byte(`{"platform":"ios"}`)); err == nil {
		t.Fatal("expected error for unrecognized schema")
	}
}

func TestParseRejectsMalformedJSON(t *testing.T) {
	if _, err := Parse([]byte(`{not json`)); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestSkippedTransformNotApplied(t *testing.T) {
	const j = `{"schema":"kseal.build-proof/v1","platform":"android","build_hash":"h","app":{},"sdk":{},"seed":{},"transforms":[{"name":"native-library-harden","status":"skipped","details":{}}],"artifacts":[]}`
	m, err := Parse([]byte(j))
	if err != nil {
		t.Fatal(err)
	}
	if m.HasAppliedTransform("native-library-harden") {
		t.Error("skipped transform must not count as applied")
	}
}
