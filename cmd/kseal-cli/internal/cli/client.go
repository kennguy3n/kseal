package cli

import (
	"context"
	"io"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
)

// CLI holds the resolved runtime context for a single invocation: the selected
// profile, effective endpoint/tenant, output format, and the lazily-built
// Connect clients. It is constructed once in root.go's PersistentPreRunE.
type CLI struct {
	cfg                *Config
	configPathResolved string
	profileName        string
	profile            *Profile

	endpoint string
	tenant   string
	output   outputFormat
	dryRun   bool
	timeout  time.Duration

	// apiKey is resolved from env/file. It is held in memory only and is never
	// written to output, logs, or the config file.
	apiKey string

	httpClient connect.HTTPClient
	out        io.Writer
	errOut     io.Writer

	// Connect clients are built lazily and cached for the lifetime of the
	// invocation. A CLI is used by a single goroutine (commands run
	// sequentially; tail polls from one goroutine), so no locking is needed.
	registryClient ksealv1connect.RegistryServiceClient
	webhookClient  ksealv1connect.WebhookServiceClient
	queryClient    ksealv1connect.QueryServiceClient
}

// clientOptions returns the Connect client options shared by every service
// client: an interceptor that attaches the bearer API key to each request.
func (c *CLI) clientOptions() []connect.ClientOption {
	return []connect.ClientOption{
		connect.WithInterceptors(authInterceptor(c.apiKey)),
	}
}

// authInterceptor injects the API key as a bearer token on every outbound
// unary request. An empty key sends no header (the server then rejects
// control-plane procedures with Unauthenticated, which the CLI surfaces).
func authInterceptor(apiKey string) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if apiKey != "" && req.Spec().IsClient {
				req.Header().Set("Authorization", "Bearer "+apiKey)
			}
			return next(ctx, req)
		}
	})
}

func (c *CLI) httpc() connect.HTTPClient {
	if c.httpClient != nil {
		return c.httpClient
	}
	return http.DefaultClient
}

func (c *CLI) registry() ksealv1connect.RegistryServiceClient {
	if c.registryClient == nil {
		c.registryClient = ksealv1connect.NewRegistryServiceClient(c.httpc(), c.endpoint, c.clientOptions()...)
	}
	return c.registryClient
}

func (c *CLI) webhooks() ksealv1connect.WebhookServiceClient {
	if c.webhookClient == nil {
		c.webhookClient = ksealv1connect.NewWebhookServiceClient(c.httpc(), c.endpoint, c.clientOptions()...)
	}
	return c.webhookClient
}

func (c *CLI) query() ksealv1connect.QueryServiceClient {
	if c.queryClient == nil {
		c.queryClient = ksealv1connect.NewQueryServiceClient(c.httpc(), c.endpoint, c.clientOptions()...)
	}
	return c.queryClient
}

// callCtx derives a per-call context honoring the configured timeout.
func (c *CLI) callCtx(parent context.Context) (context.Context, context.CancelFunc) {
	if c.timeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, c.timeout)
}

// requireTenant returns the effective tenant id for a tenant-scoped command,
// enforcing strict scoping: a tenant must come from --tenant or the active
// profile. This prevents accidental cross-tenant or unscoped operations.
func (c *CLI) requireTenant() (string, error) {
	if c.tenant != "" {
		return c.tenant, nil
	}
	return "", newUsageError("no tenant scope: pass --tenant or set one on the active profile (%q)", c.profileName)
}
