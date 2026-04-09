package mediakeys

import (
	"bytes"
	"testing"
)

type fakeExporter struct {
	label  string
	ctx    []byte
	length int
	secret []byte
	err    error
}

func (f *fakeExporter) Export(label string, ctx []byte, length int) ([]byte, error) {
	f.label = label
	f.ctx = append([]byte(nil), ctx...)
	f.length = length
	return append([]byte(nil), f.secret...), f.err
}

func TestSenderIDContextLE(t *testing.T) {
	got := SenderIDContextLE(0x0102030405060708)
	want := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	if !bytes.Equal(got, want) {
		t.Fatalf("ctx mismatch: got %x want %x", got, want)
	}
}

func TestDeriveSenderBaseSecret(t *testing.T) {
	f := &fakeExporter{secret: bytes.Repeat([]byte{0xAB}, 16)}
	got, err := DeriveSenderBaseSecret(f, 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.label != ExporterLabel {
		t.Fatalf("label mismatch: %q", f.label)
	}
	if f.length != 16 {
		t.Fatalf("length mismatch: %d", f.length)
	}
	if len(got) != 16 {
		t.Fatalf("secret len mismatch: %d", len(got))
	}
}

func TestDeriveSenderBaseSecretNilExporter(t *testing.T) {
	_, err := DeriveSenderBaseSecret(nil, 42)
	if err != ErrNilExporter {
		t.Fatalf("expected ErrNilExporter, got %v", err)
	}
}

func TestDeriveSenderBaseSecretWrongLength(t *testing.T) {
	f := &fakeExporter{secret: bytes.Repeat([]byte{0xAB}, 32)}
	_, err := DeriveSenderBaseSecret(f, 42)
	if err == nil {
		t.Fatal("expected error for wrong length secret")
	}
}
