package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/disgoorg/godave"
)

// TestCloser_Interface makes sure *session implements Closer and that the
// godave.Session returned by New is also a Closer (so integrators can
// type-assert at the call site).
func TestCloser_Interface(t *testing.T) {
	var _ Closer = (*session)(nil)
	s := New(nil, "user", testCallbacks{})
	if _, ok := s.(Closer); !ok {
		t.Fatal("godave.Session from New does not implement Closer")
	}
}

// TestClose_Idempotent verifies Close can be called multiple times
// without panicking, blocking, or double-closing the done channel.
func TestClose_Idempotent(t *testing.T) {
	s := New(nil, "123456789", testCallbacks{}).(*session)
	s.Close()
	s.Close()
	s.Close()
}

// TestClose_StopsRecoveryWatchdog verifies that Close prevents a
// pending recovery watchdog from re-arming after the timeout, which
// is the exact zombie session behavior.
func TestClose_StopsRecoveryWatchdog(t *testing.T) {
	cb := &countingCallbacks{}
	s := newRecoveryTestSession(t, cb)

	s.mu.Lock()
	s.invalidateAndResendKeyPackageLocked()
	s.mu.Unlock()

	// Wait for the first watchdog fire so we know the loop is running.
	eventually(t, func() bool {
		invalid, _ := cb.counts()

		return invalid >= 1
	}, "recovery watchdog did not fire before Close")

	invalidBefore, _ := cb.counts()
	s.Close()

	// Sleep well past the recovery timeout. If Close did not stop the
	// watchdog, it would re-fire several times.
	time.Sleep(5 * s.recoveryTimeout)

	invalidAfter, _ := cb.counts()
	if invalidAfter > invalidBefore {
		t.Fatalf("watchdog kept firing after Close: before=%d after=%d", invalidBefore, invalidAfter)
	}
}

// TestClose_StopsCommitWatchdog verifies that Close prevents the
// commit-confirm watchdog (spawned from commitProposalsLocked) from
// triggering recovery. We don't need a real commit to drive it — we
// can directly invalidate and observe that no further invalidations
// land after Close.
func TestClose_StopsCommitWatchdog(t *testing.T) {
	cb := &countingCallbacks{}
	s := newRecoveryTestSession(t, cb)

	s.Close()

	// After Close, any future invalidation must NOT spawn a watchdog
	// that reaches the callback. The lock-protected path will still
	// spawn a goroutine, but it must see shutdownCtx.Done() and exit.
	s.mu.Lock()
	s.invalidateAndResendKeyPackageLocked()
	s.mu.Unlock()

	time.Sleep(5 * s.recoveryTimeout)
	invalid, _ := cb.counts()
	if invalid != 0 {
		t.Fatalf("watchdog fired after Close: %d invalid commits", invalid)
	}
}

// TestClose_PostCloseCallbackDoesNotPanic verifies that calling any
// protocol callback after Close is safe. The contract is on the
// integrator to stop calling them; we just verify the library
// doesn't blow up if they do.
func TestClose_PostCloseCallbackDoesNotPanic(t *testing.T) {
	s := New(nil, "123456789", testCallbacks{}).(*session)
	s.OnSelectProtocolAck(1)
	s.Close()

	s.OnDavePrepareEpoch(1, 1)
	s.OnDavePrepareTransition(5, 1)
	s.OnDaveExecuteTransition(5)
	s.OnDaveMLSExternalSenderPackage([]byte{0x01})
	s.OnDaveMLSProposals([]byte{0x00, 0x00})
	s.OnDaveMLSWelcome(0, []byte{0x01})
	s.OnDaveMLSPrepareCommitTransition(0, []byte{0x01})
	if _, err := s.Encrypt(0, []byte{0x01, 0x02}, make([]byte, 64)); err != nil {
		t.Fatalf("Encrypt after Close returned error: %v", err)
	}
	if _, err := s.Decrypt("user1", []byte{0x01, 0x02}, make([]byte, 64)); err != nil {
		t.Fatalf("Decrypt after Close returned error: %v", err)
	}
}

// TestWaitShutdown_ResolvesAfterClose verifies WaitShutdown returns
// nil promptly once Close was called.
func TestWaitShutdown_ResolvesAfterClose(t *testing.T) {
	s := New(nil, "123456789", testCallbacks{}).(*session)
	s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if err := s.WaitShutdown(ctx); err != nil {
		t.Fatalf("WaitShutdown returned error after Close: %v", err)
	}
}

// TestWaitShutdown_RespectsContext verifies WaitShutdown honors ctx
// when Close was not called.
func TestWaitShutdown_RespectsContext(t *testing.T) {
	s := New(nil, "123456789", testCallbacks{}).(*session)
	// Do NOT call Close.

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := s.WaitShutdown(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// TestNewWithReporter_DeliversCloser verifies the new 3-arg
// callback receives both Reporter and Closer.
func TestNewWithReporter_DeliversCloser(t *testing.T) {
	cb := testCallbacks{}
	var gotReporter Reporter
	var gotCloser Closer

	createFunc := NewWithReporter(func(r Reporter, c Closer, _ godave.Callbacks) {
		gotReporter = r
		gotCloser = c
	})

	s := createFunc(nil, "123456789", cb)
	if s == nil {
		t.Fatal("NewWithReporter create func returned nil")
	}
	if gotReporter == nil {
		t.Fatal("Reporter not delivered")
	}
	if gotCloser == nil {
		t.Fatal("Closer not delivered")
	}
	if gotReporter.State().Ready {
		t.Fatal("a fresh session should not report E2EE-ready")
	}
	// Ensure Reporter and Closer point to the same session.
	if r, ok := s.(Reporter); !ok || r != gotReporter {
		t.Fatal("session returned does not match the Reporter delivered")
	}
	if c, ok := s.(Closer); !ok || c != gotCloser {
		t.Fatal("session returned does not match the Closer delivered")
	}
}
