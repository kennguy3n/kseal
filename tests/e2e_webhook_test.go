package tests

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/data-plane/webhook"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/auth"
	kcrypto "github.com/kennguy3n/kseal/server/shared/crypto"
)

type delivery struct {
	body      []byte
	signature string
	keyID     string
	attempt   string
	eventType string
}

func TestE2EWebhook(t *testing.T) {
	requireHarness(t)

	store := newStore(t)
	const eventType = ksealv1.EventType_EVENT_TYPE_ROOT_RISK

	t.Run("delivers_signed_event", func(t *testing.T) {
		tenant := makeTenant(t, store, "wh-deliver")
		app := makeApp(t, store, tenant.Id, "com.kseal.webhook")

		got := make(chan delivery, 4)
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			got <- delivery{
				body:      body,
				signature: r.Header.Get("X-Kseal-Signature"),
				keyID:     r.Header.Get("X-Kseal-Key-Id"),
				attempt:   r.Header.Get("X-Kseal-Delivery-Attempt"),
				eventType: r.Header.Get("X-Kseal-Event"),
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		wh := registerWebhook(t, store, tenant.Id, srv.URL, eventType)

		// srv.Client() reaches the loopback test server, opting out of the
		// production SSRF guard that blocks private/loopback delivery targets.
		d := webhook.NewDispatcher(store, webhook.DispatcherConfig{Workers: 2, BaseBackoff: 10 * time.Millisecond, HTTPClient: srv.Client()}, nil)
		defer d.Stop()

		const payload = `{"alert":"root detected"}`
		if err := d.Dispatch(context.Background(), webhook.Event{
			TenantID: tenant.Id, AppID: app.Id, Type: eventType, Payload: payload, Timestamp: time.Now().Unix(),
		}); err != nil {
			t.Fatalf("dispatch: %v", err)
		}

		select {
		case dl := <-got:
			if string(dl.body) != payload {
				t.Fatalf("payload mismatch: %q", dl.body)
			}
			if dl.eventType != eventType.String() {
				t.Fatalf("event header mismatch: %q", dl.eventType)
			}
			if dl.keyID != wh.SigningKeyId {
				t.Fatalf("key id header mismatch: %q vs %q", dl.keyID, wh.SigningKeyId)
			}
			// Verify the HMAC the tenant would verify with its provisioned secret.
			secret := webhookSecret(t, store, tenant.Id, eventType, wh.Id)
			want := hex.EncodeToString(kcrypto.HMACSHA256(secret, []byte(payload)))
			if dl.signature != want {
				t.Fatalf("HMAC signature mismatch: got %q want %q", dl.signature, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for webhook delivery")
		}
	})

	t.Run("retries_failing_endpoint_with_backoff", func(t *testing.T) {
		tenant := makeTenant(t, store, "wh-retry")
		app := makeApp(t, store, tenant.Id, "com.kseal.webhookfail")

		var attempts int32
		attemptCh := make(chan int, 8)
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&attempts, 1)
			attemptCh <- int(n)
			w.WriteHeader(http.StatusInternalServerError) // always fail
		}))
		defer srv.Close()

		registerWebhook(t, store, tenant.Id, srv.URL, eventType)

		const maxAttempts = 3
		d := webhook.NewDispatcher(store, webhook.DispatcherConfig{
			Workers: 2, MaxAttempts: maxAttempts, BaseBackoff: 10 * time.Millisecond, BreakerTrip: 100,
			HTTPClient: srv.Client(),
		}, nil)
		defer d.Stop()

		if err := d.Dispatch(context.Background(), webhook.Event{
			TenantID: tenant.Id, AppID: app.Id, Type: eventType, Payload: `{"x":1}`, Timestamp: time.Now().Unix(),
		}); err != nil {
			t.Fatalf("dispatch: %v", err)
		}

		// Expect exactly maxAttempts deliveries (1 initial + 2 retries).
		deadline := time.After(3 * time.Second)
		for i := 0; i < maxAttempts; i++ {
			select {
			case <-attemptCh:
			case <-deadline:
				t.Fatalf("only %d of %d delivery attempts observed", i, maxAttempts)
			}
		}
		// Give a brief window to ensure no 4th attempt is made.
		select {
		case n := <-attemptCh:
			t.Fatalf("unexpected extra delivery attempt #%d beyond max=%d", n, maxAttempts)
		case <-time.After(300 * time.Millisecond):
		}
		if got := atomic.LoadInt32(&attempts); got != maxAttempts {
			t.Fatalf("expected %d attempts, got %d", maxAttempts, got)
		}
	})
}

// registerWebhook registers a webhook through the real WebhookService RPC.
func registerWebhook(t *testing.T, store registry.Store, tenantID, url string, eventType ksealv1.EventType) *ksealv1.Webhook {
	t.Helper()
	svc := webhook.NewService(store)
	ctx := auth.WithTenant(context.Background(), tenantID)
	resp, err := svc.RegisterWebhook(ctx, connect.NewRequest(&ksealv1.RegisterWebhookRequest{
		TenantId: tenantID, Url: url, EventTypes: []ksealv1.EventType{eventType},
	}))
	if err != nil {
		t.Fatalf("register webhook: %v", err)
	}
	return resp.Msg.Webhook
}

// webhookSecret fetches the per-webhook signing secret provisioned to the tenant
// so the test can verify the HMAC exactly as the tenant's receiver would.
func webhookSecret(t *testing.T, store registry.Store, tenantID string, eventType ksealv1.EventType, webhookID string) []byte {
	t.Helper()
	targets, err := store.ListWebhooksForEvent(context.Background(), tenantID, eventType)
	if err != nil {
		t.Fatalf("list webhooks for event: %v", err)
	}
	for _, tw := range targets {
		if tw.Webhook.Id == webhookID {
			return tw.Secret
		}
	}
	t.Fatalf("secret for webhook %s not found", webhookID)
	return nil
}
