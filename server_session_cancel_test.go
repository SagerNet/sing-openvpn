package openvpn

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestServerControlLoopStopsOnSessionClose(t *testing.T) {
	t.Parallel()

	for _, duringRead := range []bool{false, true} {
		name := "before_control_read"
		if duringRead {
			name = "during_primary_handover"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			listenerContext, stopListener := context.WithCancel(context.Background())
			sessionContext, stopSession := context.WithCancel(listenerContext)
			session := &tlsServerSession{
				tlsPeerSession: &tlsPeerSession{},
				server:         &tlsServer{loopContext: listenerContext},
				sessionContext: sessionContext,
				cancelSession:  stopSession,
			}
			// A handover without a replacement primary stream keeps reads timing
			// out, even after Close cancels the session and closes its transport.
			session.controlStream.beginHandover(1)
			result := make(chan error, 1)
			finished := make(chan struct{})
			t.Cleanup(func() {
				stopSession()
				stopListener()
				select {
				case <-finished:
				case <-time.After(5 * time.Second):
					t.Error("control loop did not stop during cleanup")
				}
			})
			if !duringRead {
				if err := session.Close(); err != nil {
					t.Fatal(err)
				}
			}
			go func() {
				defer close(finished)
				result <- session.runControlLoop()
			}()
			if duringRead {
				waitForServerControlRead(t, session)
				if err := session.Close(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("expected session cancellation, got %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("closed session still occupies the server control loop")
			}
			if listenerContext.Err() != nil {
				t.Fatal("closing one session must not stop the listener")
			}
		})
	}
}

func waitForServerControlRead(t *testing.T, session *tlsServerSession) {
	t.Helper()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		session.controlStream.access.Lock()
		started := session.controlStream.changed != nil
		session.controlStream.access.Unlock()
		if started {
			return
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			t.Fatal("control loop did not begin waiting for the primary stream")
		}
	}
}
