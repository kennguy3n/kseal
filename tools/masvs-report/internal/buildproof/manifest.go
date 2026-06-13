// Package buildproof parses the kseal build-proof manifest emitted by the
// Android (Gradle) and iOS (Xcode) hardening plugins into one normalized model.
//
// The two plugins serialize different concrete shapes — Android emits the
// snake_case "kseal.build-proof/v1" document, iOS emits the Swift-Codable
// camelCase document — but both describe the same thing: the transforms applied
// to a build, the per-build polymorphism seed, and (iOS) Mach-O integrity
// evidence. This package hides that divergence so the report layer can reason
// about evidence uniformly and stay compatible with both as they evolve.
package buildproof

import (
	"encoding/json"
	"fmt"
)

// Manifest is the normalized, platform-neutral view of a build-proof document.
type Manifest struct {
	Schema        string
	Platform      string
	BuildHash     string
	SDKVersion    string
	AppID         string
	VersionName   string
	VersionCode   int64
	SeedDigest    string
	SeedAlgorithm string
	Transforms    []Transform
	Modules       []string
	Integrity     *Integrity
	Tooling       map[string]string
	ArtifactCount int
}

// Transform is a single hardening operation recorded in the manifest.
type Transform struct {
	Name   string
	Status string // "applied" | "skipped"; empty is treated as "applied"
	Count  int
	Detail map[string]any
}

// Applied reports whether the transform ran (vs. was reported as skipped).
func (t Transform) Applied() bool { return t.Status == "" || t.Status == "applied" }

// Integrity is the Mach-O section-hash integrity evidence (iOS only).
type Integrity struct {
	Format string
	Slices []Slice
}

// Slice is one architecture slice of a (possibly universal) Mach-O binary.
type Slice struct {
	Arch         string
	FileType     string
	PIE          bool
	Encrypted    bool
	SectionCount int
}

// Transform looks up a transform by name; ok is false when absent.
func (m *Manifest) Transform(name string) (Transform, bool) {
	for _, t := range m.Transforms {
		if t.Name == name {
			return t, true
		}
	}
	return Transform{}, false
}

// HasAppliedTransform reports whether a named transform is present and applied.
func (m *Manifest) HasAppliedTransform(name string) bool {
	t, ok := m.Transform(name)
	return ok && t.Applied()
}

const androidSchema = "kseal.build-proof/v1"

// Parse decodes a build-proof manifest, auto-detecting the plugin that produced
// it. It returns a descriptive error for unrecognized or malformed input rather
// than a partially-populated manifest, so callers fail closed.
func Parse(data []byte) (*Manifest, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("manifest is not valid JSON: %w", err)
	}
	if raw, ok := probe["schema"]; ok {
		var schema string
		if err := json.Unmarshal(raw, &schema); err == nil && schema == androidSchema {
			return parseAndroid(data)
		}
	}
	if _, ok := probe["schemaVersion"]; ok {
		return parseIOS(data)
	}
	return nil, fmt.Errorf("unrecognized build-proof schema: expected %q (Android) or a %q field (iOS)", androidSchema, "schemaVersion")
}

func parseAndroid(data []byte) (*Manifest, error) {
	var doc struct {
		Schema string `json:"schema"`
		App    struct {
			PackageID   string `json:"package_id"`
			VersionName string `json:"version_name"`
			VersionCode int64  `json:"version_code"`
		} `json:"app"`
		SDK struct {
			Version string `json:"version"`
		} `json:"sdk"`
		BuildHash string `json:"build_hash"`
		Seed      struct {
			Digest    string `json:"digest"`
			Algorithm string `json:"algorithm"`
		} `json:"seed"`
		Tooling    map[string]any `json:"tooling"`
		Transforms []struct {
			Name    string         `json:"name"`
			Status  string         `json:"status"`
			Details map[string]any `json:"details"`
		} `json:"transforms"`
		Artifacts []struct {
			Path string `json:"path"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode Android manifest: %w", err)
	}

	m := &Manifest{
		Schema:        doc.Schema,
		Platform:      "android",
		BuildHash:     doc.BuildHash,
		SDKVersion:    doc.SDK.Version,
		AppID:         doc.App.PackageID,
		VersionName:   doc.App.VersionName,
		VersionCode:   doc.App.VersionCode,
		SeedDigest:    doc.Seed.Digest,
		SeedAlgorithm: doc.Seed.Algorithm,
		Tooling:       stringifyMap(doc.Tooling),
		ArtifactCount: len(doc.Artifacts),
	}
	for _, t := range doc.Transforms {
		m.Transforms = append(m.Transforms, Transform{
			Name:   t.Name,
			Status: t.Status,
			Count:  detailInt(t.Details, "library_count", "count", "sealed", "strings"),
			Detail: t.Details,
		})
		// Transform names double as module identifiers on the Android plane,
		// which has no separate `modules` field.
		m.Modules = append(m.Modules, t.Name)
	}
	return m, nil
}

func parseIOS(data []byte) (*Manifest, error) {
	var doc struct {
		SchemaVersion string `json:"schemaVersion"`
		Platform      string `json:"platform"`
		SDKVersion    string `json:"sdkVersion"`
		BuildHash     string `json:"buildHash"`
		VersionName   string `json:"versionName"`
		VersionCode   int64  `json:"versionCode"`
		Polymorphism  struct {
			SeedDigest string `json:"seedDigest"`
			Algorithm  string `json:"algorithm"`
		} `json:"polymorphism"`
		ToolVersions map[string]string `json:"toolVersions"`
		Transforms   []struct {
			Kind      string            `json:"kind"`
			Algorithm string            `json:"algorithm"`
			Count     int               `json:"count"`
			Detail    map[string]string `json:"detail"`
		} `json:"transforms"`
		Modules   []string `json:"modules"`
		Integrity *struct {
			Format string `json:"format"`
			Slices []struct {
				Arch      string `json:"arch"`
				FileType  string `json:"fileType"`
				PIE       bool   `json:"pie"`
				Encrypted bool   `json:"encrypted"`
				Sections  []struct {
					Hash string `json:"hash"`
				} `json:"sections"`
			} `json:"slices"`
		} `json:"integrity"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode iOS manifest: %w", err)
	}

	platform := doc.Platform
	if platform == "" {
		platform = "ios"
	}
	m := &Manifest{
		Schema:        "ios:" + doc.SchemaVersion,
		Platform:      platform,
		BuildHash:     doc.BuildHash,
		SDKVersion:    doc.SDKVersion,
		VersionName:   doc.VersionName,
		VersionCode:   doc.VersionCode,
		SeedDigest:    doc.Polymorphism.SeedDigest,
		SeedAlgorithm: doc.Polymorphism.Algorithm,
		Modules:       doc.Modules,
		Tooling:       doc.ToolVersions,
	}
	for _, t := range doc.Transforms {
		detail := make(map[string]any, len(t.Detail)+1)
		for k, v := range t.Detail {
			detail[k] = v
		}
		detail["algorithm"] = t.Algorithm
		m.Transforms = append(m.Transforms, Transform{
			Name:   t.Kind,
			Status: "applied",
			Count:  t.Count,
			Detail: detail,
		})
	}
	if doc.Integrity != nil {
		integ := &Integrity{Format: doc.Integrity.Format}
		for _, s := range doc.Integrity.Slices {
			integ.Slices = append(integ.Slices, Slice{
				Arch:         s.Arch,
				FileType:     s.FileType,
				PIE:          s.PIE,
				Encrypted:    s.Encrypted,
				SectionCount: len(s.Sections),
			})
		}
		m.Integrity = integ
	}
	return m, nil
}

func stringifyMap(in map[string]any) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = fmt.Sprintf("%v", v)
	}
	return out
}

// detailInt returns the first key in details that holds a number (JSON numbers
// decode to float64), as an int. Returns 0 when none match.
func detailInt(details map[string]any, keys ...string) int {
	for _, k := range keys {
		if v, ok := details[k]; ok {
			switch n := v.(type) {
			case float64:
				return int(n)
			case int:
				return n
			}
		}
	}
	return 0
}
