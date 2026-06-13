// Command kseal-cli is the scriptable operator CLI for the kseal continuous
// app-trust platform. See docs/cli.md and ./internal/cli for details.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/kennguy3n/kseal/cli/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(cli.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
