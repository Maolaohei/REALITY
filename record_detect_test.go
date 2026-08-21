package reality

import (
	"net"
	"testing"
	"time"
)

func TestPostHandshakeRecordDetectConnTruncatedRecordDoesNotPanic(t *testing.T) {
	key := "truncated-record-test"
	GlobalPostHandshakeRecordsLens.Delete(key)
	defer GlobalPostHandshakeRecordsLens.Delete(key)

	reader, writer := net.Pipe()
	defer reader.Close()
	defer writer.Close()

	go func() {
		// TLS application-data record declares 16 bytes but provides one.
		_, _ = writer.Write([]byte{23, 3, 3, 0, 16, 0})
		_ = writer.Close()
	}()

	conn := &PostHandshakeRecordDetectConn{Conn: reader, Key: key, CcsSent: true}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = conn.Read(make([]byte, 1))
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("truncated record detection did not return")
	}

	value, ok := GlobalPostHandshakeRecordsLens.Load(key)
	if !ok {
		t.Fatal("record detection did not publish a result")
	}
	if lens := value.([]int); len(lens) != 0 {
		t.Fatalf("truncated record lengths = %v, want empty", lens)
	}
}
