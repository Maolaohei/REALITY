package reality

import (
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
)

// Event types emitted by the TLS handshake flow.
type EventType int

const (
	EventHandshakeComplete EventType = iota
	EventConnectionClosed
)

// Event represents a handshake lifecycle event.
type Event struct {
	Type        EventType
	Dest        string
	ServerName  string
	ALPN        string
	TLSVersion  uint16 // TLS 1.2 or 1.3
	Profile     *RealityProfile
	Fingerprint *targetFingerprintCache
}

// EventHandler processes an event.
type EventHandler func(event Event)

// EventBus decouples TLS handshake from cache/persist/refresh systems.
// Server() only emits events; subscribers handle the logic.
type EventBus struct {
	mu       sync.RWMutex
	handlers map[EventType][]EventHandler
	queue    chan Event
	start    sync.Once
	dropped  atomic.Int64
}

var globalEventBus = &EventBus{
	handlers: make(map[EventType][]EventHandler),
}

const (
	eventBusQueueSize = 256
	eventBusWorkers   = 4
)

func (b *EventBus) startWorkers() {
	b.start.Do(func() {
		b.mu.Lock()
		if b.handlers == nil {
			b.handlers = make(map[EventType][]EventHandler)
		}
		b.queue = make(chan Event, eventBusQueueSize)
		b.mu.Unlock()
		for range eventBusWorkers {
			go func() {
				for event := range b.queue {
					b.dispatch(event)
				}
			}()
		}
	})
}

// On registers a handler for an event type.
func (b *EventBus) On(eventType EventType, handler EventHandler) {
	b.startWorkers()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[eventType] = append(b.handlers[eventType], handler)
}

// Emit queues an event for a bounded worker set. A slow handler must never
// create one goroutine per successful handshake; a saturated queue drops only
// best-effort side work because the handshake already wrote its cache state on
// the synchronous path.
func (b *EventBus) Emit(event Event) {
	b.startWorkers()
	select {
	case b.queue <- event:
	default:
		b.dropped.Add(1)
	}
}

func (b *EventBus) dispatch(event Event) {
	b.mu.RLock()
	handlers := append([]EventHandler(nil), b.handlers[event.Type]...)
	b.mu.RUnlock()
	for _, handler := range handlers {
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "REALITY: event handler panic: %v\n%s\n", r, debug.Stack())
				}
			}()
			handler(event)
		}()
	}
}

// Reset removes all handlers (for testing).
func (b *EventBus) Reset() {
	b.startWorkers()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers = make(map[EventType][]EventHandler)
}
