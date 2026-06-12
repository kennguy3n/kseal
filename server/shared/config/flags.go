package config

import (
	"fmt"
	"strconv"
	"strings"
)

// FeatureFlags holds per-tenant feature toggles. The zero value is safe and
// reports every flag as disabled.
type FeatureFlags struct {
	// byTenant maps tenant_id -> flag name -> enabled.
	byTenant map[string]map[string]bool
	// global applies when a tenant has no specific override.
	global map[string]bool
}

// Enabled reports whether flag is on for tenantID, falling back to the global
// default and finally to false.
func (f FeatureFlags) Enabled(tenantID, flag string) bool {
	if f.byTenant != nil {
		if t, ok := f.byTenant[tenantID]; ok {
			if v, ok := t[flag]; ok {
				return v
			}
		}
	}
	if f.global != nil {
		if v, ok := f.global[flag]; ok {
			return v
		}
	}
	return false
}

// parseFeatureFlags parses a spec of the form:
//
//	"flagA=true,tenantX:flagB=true,*:flagC=false"
//
// Entries without a "tenant:" prefix (or using "*") apply globally.
func parseFeatureFlags(spec string) (FeatureFlags, error) {
	ff := FeatureFlags{
		byTenant: map[string]map[string]bool{},
		global:   map[string]bool{},
	}
	if strings.TrimSpace(spec) == "" {
		return ff, nil
	}
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		tenant := "*"
		kv := entry
		if i := strings.Index(entry, ":"); i >= 0 {
			tenant = strings.TrimSpace(entry[:i])
			kv = entry[i+1:]
		}
		eq := strings.Index(kv, "=")
		if eq < 0 {
			return ff, fmt.Errorf("feature flag %q missing '='", entry)
		}
		name := strings.TrimSpace(kv[:eq])
		val, err := strconv.ParseBool(strings.TrimSpace(kv[eq+1:]))
		if err != nil {
			return ff, fmt.Errorf("feature flag %q: %w", entry, err)
		}
		if name == "" {
			return ff, fmt.Errorf("feature flag %q has empty name", entry)
		}
		if tenant == "*" || tenant == "" {
			ff.global[name] = val
			continue
		}
		if ff.byTenant[tenant] == nil {
			ff.byTenant[tenant] = map[string]bool{}
		}
		ff.byTenant[tenant][name] = val
	}
	return ff, nil
}
