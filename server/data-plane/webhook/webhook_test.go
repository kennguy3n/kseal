package webhook

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
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/auth"
	"github.com/kennguy3n/kseal/server/shared/crypto"
)

func newStore(t *testing.T) (*registry.MemStore, *ksealv1.Tenant) {
	t.Helper()
	store := registry.NewMemStore()
	tn, err := store.CreateTenant(context.Background(), registry.CreateTenantInput{Name: "T", Slug: "t-wh"})
	if err != nil {
		t.Fatal(err)
	}
	return store, tn
}

func TestWebhookServiceCRUD(t *testing.T) {
	store, tn := newStore(t)
	svc := NewService(store)
	ctx := auth.WithTenant(context.Background(), tn.Id)

	reg, err := svc.RegisterWebhook(ctx, connect.NewRequest(&ksealv1.RegisterWebhookRequest{
		TenantId: tn.Id, Url: "https://example.com/h", EventTypes: []ksealv1.EventType{ksealv1.EventType_EVENT_TYPE_ROOT_RISK},
	}))
	if err != nil {
		t.Fatal(err)
	}
	list, err := svc.ListWebhooks(ctx, connect.NewRequest(&ksealv1.ListWebhooksRequest{TenantId: tn.Id}))
	if err != nil || len(list.Msg.Webhooks) != 1 {
		t.Fatalf("list: %v %d", err, len(list.Msg.Webhooks))
	}
	del, err := svc.DeleteWebhook(ctx, connect.NewRequest(&ksealv1.DeleteWebhookRequest{TenantId: tn.Id, Id: reg.Msg.Webhook.Id}))
	if err != nil || !del.Msg.Deleted {
		t.Fatalf("delete: %v %v", err, del.Msg.Deleted)
	}
}

func TestWebhookServiceCrossTenantDenied(t *testing.T) {
	store, tn := newStore(t)
	svc := NewService(store)
	ctx := auth.WithTenant(context.Background(), "other-tenant")
	_, err := svc.RegisterWebhook(ctx, connect.NewRequest(&ksealv1.RegisterWebhookRequest{TenantId: tn.Id, Url: "https://x"}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expected permission denied, got %v", err)
	}
}

func TestDispatcherSignsAndDelivers(t *testing.T) {
	store, tn := newStore(t)
	type received struct {
		body string
		sig  string
	}
	got := make(chan received, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- received{body: string(b), sig: r.Header.Get("X-Kseal-Signature")}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh, err := store.CreateWebhook(context.Background(), tn.Id, srv.URL, []ksealv1.EventType{ksealv1.EventType_EVENT_TYPE_ROOT_RISK})
	if err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(store, DispatcherConfig{Workers: 1, MaxAttempts: 3, BaseBackoff: time.Millisecond}, nil)
	defer d.Stop()

	if err := d.Dispatch(context.Background(), Event{TenantID: tn.Id, Type: ksealv1.EventType_EVENT_TYPE_ROOT_RISK, Payload: `{"hello":"world"}`}); err != nil {
		t.Fatal(err)
	}

	select {
	case r := <-got:
		if r.body != `{"hello":"world"}` {
			t.Fatalf("body mismatch: %s", r.body)
		}
		// Recover the secret to verify the HMAC signature.
		secrets, _ := store.ListWebhooksForEvent(context.Background(), tn.Id, ksealv1.EventType_EVENT_TYPE_ROOT_RISK)
		var secret []byte
		for _, s := range secrets {
			if s.Webhook.Id == wh.Id {
				secret = s.Secret
			}
		}
		want := hex.EncodeToString(crypto.HMACSHA256(secret, []byte(r.body)))
		if r.sig != want {
			t.Fatalf("signature mismatch: got %s want %s", r.sig, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook not delivered")
	}
}

func TestDispatcherSubmitDelivers(t *testing.T) {
	store, tn := newStore(t)
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, err := store.CreateWebhook(context.Background(), tn.Id, srv.URL, []ksealv1.EventType{ksealv1.EventType_EVENT_TYPE_ROOT_RISK}); err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(store, DispatcherConfig{Workers: 1, MaxAttempts: 1, BaseBackoff: time.Millisecond}, nil)
	defer d.Stop()

	// Submit is the async, non-blocking entry point used by the ingest writer:
	// subscriber resolution happens off the caller's goroutine.
	d.Submit(Event{TenantID: tn.Id, Type: ksealv1.EventType_EVENT_TYPE_ROOT_RISK, Payload: `{"k":"v"}`})

	select {
	case b := <-got:
		if b != `{"k":"v"}` {
			t.Fatalf("body mismatch: %s", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("submitted event not delivered")
	}
}

// TestDispatcherStopWithPendingRetryNoPanic exercises the shutdown race: a retry
// timer can fire after Stop() has closed the worker queue. The stopped flag must
// make the late enqueue a no-op instead of panicking on a closed channel.
func TestDispatcherStopWithPendingRetryNoPanic(t *testing.T) {
	store, tn := newStore(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError) // always fail -> schedules a retry
	}))
	defer srv.Close()

	if _, err := store.CreateWebhook(context.Background(), tn.Id, srv.URL, []ksealv1.EventType{ksealv1.EventType_EVENT_TYPE_DEBUGGER}); err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(store, DispatcherConfig{Workers: 1, MaxAttempts: 5, BaseBackoff: 50 * time.Millisecond}, nil)
	_ = d.Dispatch(context.Background(), Event{TenantID: tn.Id, Type: ksealv1.EventType_EVENT_TYPE_DEBUGGER, Payload: "{}"})
	time.Sleep(10 * time.Millisecond) // let the first attempt fail and schedule a retry
	d.Stop()
	// Give the pending retry timer time to fire against the stopped dispatcher.
	time.Sleep(100 * time.Millisecond)
}

func TestDispatcherRetriesThenSucceeds(t *testing.T) {
	store, tn := newStore(t)
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, err := store.CreateWebhook(context.Background(), tn.Id, srv.URL, []ksealv1.EventType{ksealv1.EventType_EVENT_TYPE_DEBUGGER}); err != nil {
		t.Fatal(err)
	}
	d := NewDispatcher(store, DispatcherConfig{Workers: 1, MaxAttempts: 3, BaseBackoff: time.Millisecond}, nil)
	defer d.Stop()
	_ = d.Dispatch(context.Background(), Event{TenantID: tn.Id, Type: ksealv1.EventType_EVENT_TYPE_DEBUGGER, Payload: "{}"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&attempts) >= 3 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("expected 3 attempts, got %d", atomic.LoadInt32(&attempts))
}
