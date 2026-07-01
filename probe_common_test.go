package reality

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// buildFakeServerHello builds a minimal ServerHello record with a given
// cipherSuite. The record contains a valid TLS record header and a ServerHello
// body that is parseable by serverHelloMsg.unmarshal.
func buildFakeServerHello(cs uint16) []byte {
	// ServerHello body: version(2) + random(32) + sessionIDLen(1) + cipherSuite(2) + compression(1) = 38
	// Handshake header: type(1) + length(3) = 4
	// Total record payload = 4 + 38 = 42
	payloadLen := 42
	record := make([]byte, recordHeaderLen+payloadLen)
	record[0] = byte(recordTypeHandshake)
	// TLS 1.2 version = 0x0303
	record[1] = 0x03
	record[2] = 0x03
	record[3] = byte(payloadLen >> 8)
	record[4] = byte(payloadLen)
	// Handshake type = ServerHello (2)
	record[5] = 2
	// Handshake length (3 bytes, big-endian) = payloadLen - 4 = 38
	record[6] = 0
	record[7] = 0
	record[8] = byte(payloadLen - 4)
	// Server version = TLS 1.2 (0x0303)
	record[9] = 0x03
	record[10] = 0x03
	// Random (32 bytes, offset 11-42) — zeros
	// Session ID length = 0
	record[43] = 0
	// Cipher suite
	record[44] = byte(cs >> 8)
	record[45] = byte(cs)
	// Compression method
	record[46] = 0
	return record
}

// buildFakeCCS builds a ChangeCipherSpec record (always 6 bytes).
func buildFakeCCS() []byte {
	return []byte{
		byte(recordTypeChangeCipherSpec),
		0x03, 0x03, // TLS 1.2
		0, 1, // length = 1
		1, // CCS body
	}
}

func TestParseRecordLens_ServerHelloOnly(t *testing.T) {
	cs := uint16(0x1301)
	record := buildFakeServerHello(cs)

	lens, gotCS, ok := parseRecordLens(record)
	if !ok {
		t.Fatal("parseRecordLens failed")
	}
	if gotCS != cs {
		t.Fatalf("cipher suite: got 0x%04x, want 0x%04x", gotCS, cs)
	}
	if lens[0] != recordHeaderLen+42 {
		t.Fatalf("record[0] length: got %d, want %d", lens[0], recordHeaderLen+42)
	}
	for i := 1; i < 7; i++ {
		if lens[i] != 0 {
			t.Fatalf("record[%d] should be 0, got %d", i, lens[i])
		}
	}
}

func TestParseRecordLens_ServerHelloPlusCCS(t *testing.T) {
	cs := uint16(0x1301)
	var buf bytes.Buffer
	buf.Write(buildFakeServerHello(cs))
	buf.Write(buildFakeCCS())

	lens, gotCS, ok := parseRecordLens(buf.Bytes())
	if !ok {
		t.Fatal("parseRecordLens failed")
	}
	if gotCS != cs {
		t.Fatalf("cipher suite: got 0x%04x, want 0x%04x", gotCS, cs)
	}
	if lens[0] == 0 {
		t.Fatal("record[0] should be non-zero")
	}
	if lens[1] != 6 {
		t.Fatalf("record[1] (CCS) length: got %d, want 6", lens[1])
	}
}

func TestParseRecordLens_EmptyData(t *testing.T) {
	_, _, ok := parseRecordLens(nil)
	if ok {
		t.Fatal("expected failure on nil data")
	}
	_, _, ok = parseRecordLens([]byte{})
	if ok {
		t.Fatal("expected failure on empty data")
	}
}

func TestParseRecordLens_InvalidVersion(t *testing.T) {
	record := make([]byte, 10)
	record[0] = byte(recordTypeHandshake)
	record[1] = 0x03
	record[2] = 0x04 // TLS 1.3, not 1.2
	record[3] = 0
	record[4] = 5

	_, _, ok := parseRecordLens(record)
	if ok {
		t.Fatal("expected failure for invalid TLS version")
	}
}

func TestParseRecordLens_WrongHandshakeType(t *testing.T) {
	record := make([]byte, 10)
	record[0] = byte(recordTypeHandshake)
	record[1] = 0x03
	record[2] = 0x03
	record[3] = 0
	record[4] = 5
	record[5] = typeClientHello // wrong: should be ServerHello

	_, _, ok := parseRecordLens(record)
	if ok {
		t.Fatal("expected failure for wrong handshake type")
	}
}

func TestParseRecordLens_RecordTooLarge(t *testing.T) {
	record := make([]byte, recordHeaderLen+10)
	record[0] = byte(recordTypeHandshake)
	record[1] = 0x03
	record[2] = 0x03
	record[3] = byte(maxTLSRecordPayload >> 8)
	record[4] = byte(maxTLSRecordPayload)
	record[5] = 2 // ServerHello

	_, _, ok := parseRecordLens(record)
	if ok {
		t.Fatal("expected failure for oversized record")
	}
}

func TestParseRecordLens_CCSWrongLength(t *testing.T) {
	cs := uint16(0x1301)
	var buf bytes.Buffer
	buf.Write(buildFakeServerHello(cs))
	// CCS with wrong length (not 6 bytes total)
	ccs := []byte{
		byte(recordTypeChangeCipherSpec),
		0x03, 0x03,
		0, 5, // length = 5 (should be 1, making total 6)
		1, 2, 3, 4, 5,
	}
	buf.Write(ccs)

	_, _, ok := parseRecordLens(buf.Bytes())
	if ok {
		t.Fatal("expected failure for CCS with wrong length")
	}
}

func TestParseRecordLens_PartialCapture(t *testing.T) {
	// A complete ServerHello is recordHeaderLen+42 = 47 bytes.
	// With less than 47 bytes, the record is incomplete and cannot be parsed.
	record := buildFakeServerHello(0x1301)

	// Truncated: only 10 bytes (header + partial body)
	_, _, ok := parseRecordLens(record[:recordHeaderLen+5])
	if ok {
		t.Fatal("incomplete ServerHello should not parse as ok")
	}

	// Full ServerHello should parse fine
	lens, cs, ok := parseRecordLens(record)
	if !ok {
		t.Fatal("complete ServerHello should parse successfully")
	}
	if cs != 0x1301 {
		t.Fatalf("cipher suite: got 0x%04x, want 0x%04x", cs, 0x1301)
	}
	if lens[0] == 0 {
		t.Fatal("record[0] should be non-zero")
	}
}

func TestParseRecordLens_InvalidNonHandshakeType(t *testing.T) {
	record := make([]byte, 10)
	record[0] = byte(recordTypeApplicationData)
	record[1] = 0x03
	record[2] = 0x03
	record[3] = 0
	record[4] = 5

	_, _, ok := parseRecordLens(record)
	if ok {
		t.Fatal("expected failure for non-handshake record type")
	}
}

// probeTestConn is a minimal net.Conn implementation for testing probeConn.
type probeTestConn struct {
	io.Reader
	io.Writer
	io.Closer
}

func (c *probeTestConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *probeTestConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *probeTestConn) SetDeadline(t time.Time) error      { return nil }
func (c *probeTestConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *probeTestConn) SetWriteDeadline(t time.Time) error { return nil }

func TestProbeConn_CapturesReadBytes(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()

	pc := newProbeConn(&probeTestConn{Reader: pr, Writer: pw, Closer: pr})

	go func() {
		pw.Write([]byte("hello from server"))
		pw.Close()
	}()

	buf := make([]byte, 100)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf[:n]) != "hello from server" {
		t.Fatalf("got %q, want %q", string(buf[:n]), "hello from server")
	}

	captured := pc.capturedBytes()
	if string(captured) != "hello from server" {
		t.Fatalf("captured %q, want %q", string(captured), "hello from server")
	}
}

func TestProbeConn_CapturesMultipleReads(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()

	pc := newProbeConn(&probeTestConn{Reader: pr, Writer: pw, Closer: pr})

	go func() {
		pw.Write([]byte("aaa"))
		pw.Write([]byte("bbb"))
		pw.Write([]byte("ccc"))
		pw.Close()
	}()

	buf := make([]byte, 100)
	var all []byte
	for {
		n, err := pc.Read(buf)
		if n > 0 {
			all = append(all, buf[:n]...)
		}
		if err != nil {
			break
		}
	}

	if string(all) != "aaabbbccc" {
		t.Fatalf("got %q, want %q", string(all), "aaabbbccc")
	}

	captured := pc.capturedBytes()
	if string(captured) != "aaabbbccc" {
		t.Fatalf("captured %q, want %q", string(captured), "aaabbbccc")
	}
}

func TestSelectFingerprintAndALPN(t *testing.T) {
	tests := []struct {
		alpn       int
		wantClient string
		protoCount int
	}{
		{0, "Golang", 0},
		{1, "Golang", 1},
		{2, "Chrome", 2},
	}

	for _, tt := range tests {
		fp, protos := selectFingerprintAndALPN(tt.alpn)
		if fp.Client != tt.wantClient {
			t.Errorf("alpn=%d: fingerprint.Client = %s, want %s", tt.alpn, fp.Client, tt.wantClient)
		}
		if len(protos) != tt.protoCount {
			t.Errorf("alpn=%d: len(protos) = %d, want %d", tt.alpn, len(protos), tt.protoCount)
		}
	}
}
