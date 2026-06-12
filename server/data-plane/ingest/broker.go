package ingest

import (
	"context"
	"errors"
	"sync"
)

// ErrBrokerFull is returned when the in-process queue is saturated; the edge
// sheds load rather than blocking the request path.
var ErrBrokerFull = errors.New("ingest: broker queue full")

// Broker decouples accept-time from write-time. A Kafka-backed broker can
// implement this interface without changing the ingest service.
type Broker interface {
	Publish(ctx context.Context, e StoredEvent) error
	Consume() <-chan StoredEvent
	Close()
}

// ChannelBroker is an in-process, buffered-channel broker.
type ChannelBroker struct {
	ch        chan StoredEvent
	closeOnce sync.Once
}

// NewChannelBroker builds a broker with the given buffer capacity.
func NewChannelBroker(buffer int) *ChannelBroker {
	if buffer <= 0 {
		buffer = 4096
	}
	return &ChannelBroker{ch: make(chan StoredEvent, buffer)}
}

// Publish enqueues without blocking, returning ErrBrokerFull when saturated.
func (b *ChannelBroker) Publish(ctx context.Context, e StoredEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case b.ch <- e:
		return nil
	default:
		return ErrBrokerFull
	}
}

// Consume exposes the receive side for the writer.
func (b *ChannelBroker) Consume() <-chan StoredEvent { return b.ch }

// Close closes the underlying channel exactly once.
func (b *ChannelBroker) Close() {
	b.closeOnce.Do(func() { close(b.ch) })
}
