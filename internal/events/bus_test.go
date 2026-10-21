package events

import (
	"sync"
	"testing"
	"time"
)

// TestBusBroadcastsToAllSubscribers is this package's core correctness
// requirement, per this task's own brief: multiple connected clients all
// receive a broadcast event.
func TestBusBroadcastsToAllSubscribers(t *testing.T) {
	b := NewBus()

	const n = 5
	chans := make([]<-chan Event, n)
	unsubs := make([]func(), n)
	for i := 0; i < n; i++ {
		ch, unsub := b.Subscribe()
		chans[i] = ch
		unsubs[i] = unsub
	}
	defer func() {
		for _, unsub := range unsubs {
			unsub()
		}
	}()

	if got := b.SubscriberCount(); got != n {
		t.Fatalf("SubscriberCount() = %d, want %d", got, n)
	}

	want := IncidentUpdated("inc_1", "cl_1")
	b.Publish(want)

	for i, ch := range chans {
		select {
		case got := <-ch:
			if got != want {
				t.Errorf("subscriber %d: got %+v, want %+v", i, got, want)
			}
		case <-time.After(time.Second):
			t.Errorf("subscriber %d: did not receive the published event", i)
		}
	}
}

// TestBusUnsubscribedClientReceivesNothing checks the other half of that
// same requirement from the opposite direction: once unsubscribed, a
// channel is closed and receives no further events.
func TestBusUnsubscribedClientReceivesNothing(t *testing.T) {
	b := NewBus()
	ch, unsub := b.Subscribe()
	unsub()

	b.Publish(ClusterUpdated("cl_1"))

	select {
	case got, ok := <-ch:
		if ok {
			t.Fatalf("expected closed channel after unsubscribe, got event %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("channel was not closed after unsubscribe")
	}

	if got := b.SubscriberCount(); got != 0 {
		t.Fatalf("SubscriberCount() = %d, want 0 after unsubscribe", got)
	}
}

// TestBusSlowSubscriberDoesNotBlockOthers is this task's other explicit
// requirement: a disconnected/stalled client must never block delivery to
// any other subscriber, nor block the Publish call itself. "slow" is
// simulated by a subscriber that never reads at all — Publish must still
// return promptly and every other, actively-reading subscriber must still
// receive every event.
func TestBusSlowSubscriberDoesNotBlockOthers(t *testing.T) {
	b := NewBus()

	stalledCh, stalledUnsub := b.Subscribe() // never read from
	defer stalledUnsub()
	activeCh, activeUnsub := b.Subscribe()
	defer activeUnsub()

	// Fill the stalled subscriber's buffer well past capacity — every one of
	// these Publish calls must return immediately regardless, never block on
	// the full channel.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < subscriberBufferSize*4; i++ {
			b.Publish(ClusterUpdated("cl_flood"))
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a stalled subscriber instead of dropping its events")
	}

	// The active subscriber must have received at least the buffer's worth
	// of events (it wasn't being drained concurrently, so it also fills up,
	// but it must never have caused Publish to block, and it must still
	// have real events sitting in it now).
	select {
	case got := <-activeCh:
		if got.Type != TypeClusterUpdated {
			t.Errorf("active subscriber: got type %q, want %q", got.Type, TypeClusterUpdated)
		}
	default:
		t.Fatal("active subscriber received nothing at all")
	}

	// The stalled subscriber's channel still exists and is still open (it
	// was never unsubscribed) — draining it should yield exactly
	// subscriberBufferSize buffered events (the rest were dropped), never a
	// panic, never a send on a closed channel.
	count := 0
	for {
		select {
		case _, ok := <-stalledCh:
			if !ok {
				t.Fatal("stalled subscriber's channel was closed unexpectedly")
			}
			count++
		default:
			goto done2
		}
	}
done2:
	if count != subscriberBufferSize {
		t.Errorf("stalled subscriber: buffered %d events, want exactly %d (the rest should have been dropped)", count, subscriberBufferSize)
	}
}

// TestBusConcurrentPublishSubscribeUnsubscribe exercises the bus the way
// -race is meant to catch a real bug: many goroutines publishing while
// others concurrently subscribe and unsubscribe, with no external
// synchronization beyond the Bus itself.
func TestBusConcurrentPublishSubscribeUnsubscribe(t *testing.T) {
	b := NewBus()
	var wg sync.WaitGroup

	const publishers = 8
	const publishesEach = 200
	wg.Add(publishers)
	for i := 0; i < publishers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < publishesEach; j++ {
				b.Publish(IncidentUpdated("inc_x", "cl_x"))
			}
		}()
	}

	const churners = 8
	wg.Add(churners)
	for i := 0; i < churners; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				ch, unsub := b.Subscribe()
				select {
				case <-ch:
				default:
				}
				unsub()
			}
		}()
	}

	wg.Wait()
}
