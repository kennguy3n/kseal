// Package migrations embeds the ordered SQL schema migrations for the kseal
// control plane. They are applied on server startup by the shared db migration
// runner and are safe to run repeatedly (idempotent, checksum-guarded).
package migrations

import "embed"

// FS holds every numbered *.sql migration, applied in lexical order.
//
//go:embed *.sql
var FS embed.FS
