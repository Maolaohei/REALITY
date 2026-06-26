package reality

import "sync"

// Event types emitted by the TLS handshake flow.
type EventType int

const (
	EventHandshakeComplete EventType = iota
	EventConnectionClosed
)

// Event represents a handshake lifecycle event.
type Event struct {
	Type     EventType
	Dest     string
	ServerName string
	ALPN     string
	Profile  *RealityProfile
	Fingerprint *targetFingerprintCache
}

// EventHandler processes an event.
type EventHandler func(event Event)

// EventBus decouples TLS handshake from cache/persist/refresh systems.
// Server() only emits events; subscribers handle the logic.
type EventBus struct {
	mu       sync.RWMutex
	handlers map[EventType][]EventHandler
}

var globalEventBus = &EventBus{
	handlers: make(map[EventType][]EventHandler),
}

// On registers a handler for an event type.
func (b *EventBus) On(eventType EventType, handler EventHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[eventType] = append(b.handlers[eventType], handler)
}

// Emit fires an event to all registered handlers.
func (b *EventBus) Emit(event Event) {
	b.mu.RLock()
	handlers := b.handlers[event.Type]
	b.mu.RUnlock()

	for _, h := range handlers {
		h(event)
	}
}

// Reset removes all handlers (for testing).
func (b *EventBus) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers = make(map[EventType][]EventHandler)
}
