// Package middleware provides the Connect interceptors and HTTP middleware that
// implement the cross-cutting concerns shared by every kseal service: request
// IDs, structured logging, tracing, panic recovery, tenant-context injection,
// per-tenant rate limiting, and CORS.
package middleware

import (
	"os"
	"strings"

	"github.com/rs/zerolog"
)

// NewLogger builds a zerolog logger at the configured level. In dev it pretty
// prints to stderr; otherwise it emits JSON for log pipelines.
func NewLogger(level, env string) zerolog.Logger {
	lvl, err := zerolog.ParseLevel(strings.ToLower(level))
	if err != nil || level == "" {
		lvl = zerolog.InfoLevel
	}
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs

	var logger zerolog.Logger
	switch strings.ToLower(env) {
	case "dev", "development", "":
		logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
	default:
		logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
	}
	return logger.Level(lvl)
}
