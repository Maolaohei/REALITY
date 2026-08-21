package reality

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestEventBusBoundedWorkersUnderBlockedHandler(t *testing.T) {
	b := &EventBus{}
	block := make(chan struct{})
	b.On(EventHandshakeComplete, func(Event) { <-block })

	before := runtime.NumGoroutine()
	for i := 0; i < 1000; i++ {
		b.Emit(Event{Type: EventHandshakeComplete})
	}
	time.Sleep(50 * time.Millisecond)
	after := runtime.NumGoroutine()
	if delta := after - before; delta > eventBusWorkers+8 {
		t.Fatalf("blocked event handler spawned %d goroutines, want bounded by workers", delta)
	}
	if b.dropped.Load() == 0 {
		t.Fatal("saturated event queue did not record drops")
	}
	close(block)
}

func TestEventBusHandlerPanicDoesNotStopWorker(t *testing.T) {
	b := &EventBus{}
	var once sync.Once
	done := make(chan struct{})
	b.On(EventHandshakeComplete, func(Event) {
		once.Do(func() { panic("expected") })
		close(done)
	})
	b.Emit(Event{Type: EventHandshakeComplete})
	b.Emit(Event{Type: EventHandshakeComplete})
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not process event after handler panic")
	}
}
