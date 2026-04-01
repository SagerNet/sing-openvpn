package test

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/sagernet/sing-openvpn"
	E "github.com/sagernet/sing/common/exceptions"
)

func TestTunnelConfigurationCallbacksRemainOrderedAcrossReconnect(t *testing.T) {
	listenAddress := reserveListenAddressForProtocol(t, "tcp")
	firstServerContext, cancelFirstServerContext := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancelFirstServerContext()
	firstServer := startSupervisorTLSServer(t, firstServerContext, listenAddress)
	defer firstServer.Close()

	firstCallbackEntered := make(chan TunnelConfigurationEvent, 1)
	laterCallbackEntered := make(chan TunnelConfigurationEvent, 2)
	releaseFirstCallback := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() {
			close(releaseFirstCallback)
		})
	})
	var callbackCount atomic.Uint32
	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancelClientContext()
	client, err := NewClient(ClientOptions{
		Context:   clientContext,
		Mode:      ModeTLS,
		Transport: clientTransportOptions(t, listenAddress, "tcp"),
		TLS: ClientTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Pull: ClientPullOptions{Enabled: true},
		OnTunnelConfiguration: func(event TunnelConfigurationEvent) error {
			if callbackCount.Add(1) == 1 {
				firstCallbackEntered <- event
				<-releaseFirstCallback
				return nil
			}
			laterCallbackEntered <- event
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}

	firstEvent := waitForSupervisorTunnelConfigurationEvent(t, firstCallbackEntered, 10*time.Second)
	if firstEvent.Reason != TunnelConfigurationEventInitial {
		t.Fatalf("unexpected first event reason: %s", firstEvent.Reason)
	}
	err = tryEchoClientThroughServer(client, firstServer, []byte("before-ordered-reconnect"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = firstServer.Close()
	if err != nil {
		t.Fatal(err)
	}
	waitForClientNotReady(t, client, 10*time.Second)

	secondServerContext, cancelSecondServerContext := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancelSecondServerContext()
	secondServer := startSupervisorTLSServer(t, secondServerContext, listenAddress)
	defer secondServer.Close()
	waitForClientReady(t, client, 20*time.Second)
	err = tryEchoClientThroughServer(client, secondServer, []byte("after-ordered-reconnect"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-laterCallbackEntered:
		t.Fatalf("later callback entered while the first callback was blocked: %s", event.Reason)
	default:
	}

	releaseOnce.Do(func() {
		close(releaseFirstCallback)
	})
	secondEvent := waitForSupervisorTunnelConfigurationEvent(t, laterCallbackEntered, 5*time.Second)
	if secondEvent.Reason != TunnelConfigurationEventInitial {
		t.Fatalf("unexpected second event reason: %s", secondEvent.Reason)
	}
}

func TestClientCloseDropsQueuedTunnelConfigurationCallbacksWithoutWaitingForActive(t *testing.T) {
	listenAddress := reserveListenAddressForProtocol(t, "tcp")
	firstServerContext, cancelFirstServerContext := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancelFirstServerContext()
	firstServer := startSupervisorTLSServer(t, firstServerContext, listenAddress)
	defer firstServer.Close()

	firstCallbackEntered := make(chan struct{})
	firstCallbackReturned := make(chan struct{})
	unexpectedCallback := make(chan TunnelConfigurationEvent, 1)
	releaseFirstCallback := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() {
			close(releaseFirstCallback)
		})
	})
	var callbackCount atomic.Uint32
	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancelClientContext()
	client, err := NewClient(ClientOptions{
		Context:   clientContext,
		Mode:      ModeTLS,
		Transport: clientTransportOptions(t, listenAddress, "tcp"),
		TLS: ClientTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Pull: ClientPullOptions{Enabled: true},
		OnTunnelConfiguration: func(event TunnelConfigurationEvent) error {
			if callbackCount.Add(1) != 1 {
				unexpectedCallback <- event
				return nil
			}
			close(firstCallbackEntered)
			<-releaseFirstCallback
			close(firstCallbackReturned)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-firstCallbackEntered:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the active callback")
	}
	err = firstServer.Close()
	if err != nil {
		t.Fatal(err)
	}
	waitForClientNotReady(t, client, 10*time.Second)

	secondServerContext, cancelSecondServerContext := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancelSecondServerContext()
	secondServer := startSupervisorTLSServer(t, secondServerContext, listenAddress)
	defer secondServer.Close()
	waitForClientReady(t, client, 20*time.Second)
	err = tryEchoClientThroughServer(client, secondServer, []byte("queued-before-close"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	closeReturned := make(chan error, 1)
	go func() {
		closeReturned <- client.Close()
	}()
	select {
	case closeErr := <-closeReturned:
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Fatal(closeErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited for the active tunnel configuration callback")
	}
	select {
	case <-firstCallbackReturned:
		t.Fatal("the active callback returned before it was released")
	default:
	}

	releaseOnce.Do(func() {
		close(releaseFirstCallback)
	})
	select {
	case <-firstCallbackReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the active callback to return")
	}
	select {
	case event := <-unexpectedCallback:
		t.Fatalf("queued callback ran after Close: %s", event.Reason)
	case <-time.After(500 * time.Millisecond):
	}
}

func waitForClientNotReady(t *testing.T, client *Client, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !client.Ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for client to leave ready state")
}
