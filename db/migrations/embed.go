// Package migrations embeds every `iam` schema migration into the binary,
// so a process applying them never depends on a SQL file existing on disk
// next to it: internal/migrate reads migration sources from FS, not the
// local filesystem (anti-goal A1 — adding authorization to a Go binary
// must need nothing beyond a Postgres connection string).
package migrations

import "embed"

// FS holds every *.sql migration file embedded at build time.
//
//go:embed *.sql
var FS embed.FS
