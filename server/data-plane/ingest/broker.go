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

// PersistAcker is optionally implemented by a Broker whose durable read
// position must only advance after events are persisted to the analytics store.
// The Writer calls Ack(n) after each successful flush, naming the number of
// events — in Consume() hand-off (FIFO) order — that are now durable. This makes
// the pipeline genuinely at-least-once through the store: a record's offset is
// committed only after ClickHouse has it, so a crash (or a ClickHouse outage)
// redelivers rather than loses, and the store's id-keyed dedup collapses the
// retry. Brokers with no durable position (the in-process ChannelBroker) simply
// do not implement this and the Writer's Ack call is a no-op.
type PersistAcker interface {
	Ack(n int)
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
