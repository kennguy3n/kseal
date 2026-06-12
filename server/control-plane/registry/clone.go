package registry

import (
	"google.golang.org/protobuf/proto"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// The clone helpers return deep copies so the in-memory store never leaks
// internal pointers to callers (matching the copy semantics of the Postgres
// store, which always materializes fresh structs).

func cloneTenant(t *ksealv1.Tenant) *ksealv1.Tenant   { return proto.Clone(t).(*ksealv1.Tenant) }
func cloneApp(a *ksealv1.App) *ksealv1.App             { return proto.Clone(a).(*ksealv1.App) }
func cloneBuild(b *ksealv1.Build) *ksealv1.Build       { return proto.Clone(b).(*ksealv1.Build) }
func clonePolicy(p *ksealv1.Policy) *ksealv1.Policy    { return proto.Clone(p).(*ksealv1.Policy) }
func cloneWebhook(w *ksealv1.Webhook) *ksealv1.Webhook { return proto.Clone(w).(*ksealv1.Webhook) }

func cloneProfile(pp *ksealv1.ProtectionProfile) *ksealv1.ProtectionProfile {
	return proto.Clone(pp).(*ksealv1.ProtectionProfile)
}

func cloneSigningKey(k *SigningKey) *SigningKey {
	cp := *k
	cp.Public = append([]byte(nil), k.Public...)
	cp.Private = append([]byte(nil), k.Private...)
	return &cp
}
