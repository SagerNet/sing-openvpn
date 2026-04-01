package test

import (
	"context"
	"errors"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	E "github.com/sagernet/sing/common/exceptions"
)

func waitForClientReady(t *testing.T, client *openvpn.Client, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if client.Ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for client ready")
}

func waitForClientTerminalError(t *testing.T, client *openvpn.Client, timeout time.Duration, target error) error {
	t.Helper()
	readContext, cancelRead := context.WithTimeout(context.Background(), timeout)
	defer cancelRead()
	_, err := client.ReadDataPacket(readContext)
	if err == nil {
		t.Fatal("expected terminal error, got data packet")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("timed out waiting for client terminal error")
	}
	if target != nil && !errors.Is(err, target) && !E.IsMulti(err, target) {
		t.Fatalf("unexpected terminal error: %v", err)
	}
	return err
}
