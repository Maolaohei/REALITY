package reality

import (
	"errors"
	"testing"
	"time"
)

func TestDoProbePanicReleasesSingleflightWaiters(t *testing.T) {
	m := NewCacheManager()
	key := "panic-flight"
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		defer func() { _ = recover() }()
		_, _ = m.DoProbe(key, func() (*RealityProfile, error) {
			panic("probe panic")
		})
	}()
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("panic probe did not return")
	}

	result := make(chan error, 1)
	go func() {
		_, err := m.DoProbe(key, func() (*RealityProfile, error) {
			return nil, errors.New("second probe ran")
		})
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil || err.Error() != "second probe ran" {
			t.Fatalf("second probe err = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("singleflight waiter remained blocked after panic")
	}
}
