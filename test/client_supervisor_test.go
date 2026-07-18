package test

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	. "github.com/sagernet/sing-openvpn"
	E "github.com/sagernet/sing/common/exceptions"
)

func TestClientSupervisorAdvancesResolvedAddressIndex(t *testing.T) {
	t.Parallel()
	listenAddress := reserveListenAddressForProtocol(t, "tcp")
	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelServerContext()
	server := startSupervisorTLSServer(t, serverContext, listenAddress)
	defer server.Close()

	addressIndexes := make(chan int, 4)
	eventCh := make(chan TunnelConfigurationEvent, 2)
	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelClientContext()
	client, err := NewClient(ClientOptions{
		Context: clientContext,
		Mode:    ModeTLS,
		Transport: ClientTransportOptions{
			Remotes:  []Remote{{Host: "resolved-address.test", Port: 1194, Protocol: "tcp"}},
			Protocol: "tcp",
			DialContextWithAddressIndex: func(ctx context.Context, network string, _ string, addressIndex int) (net.Conn, error) {
				addressIndexes <- addressIndex
				if addressIndex == 0 {
					return nil, E.New("first resolved address unavailable")
				}
				if addressIndex > 1 {
					return nil, ErrRemoteAddressExhausted
				}
				return (&net.Dialer{}).DialContext(ctx, network, listenAddress)
			},
		},
		TLS: ClientTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Pull: ClientPullOptions{Enabled: true},
		OnTunnelConfiguration: func(event TunnelConfigurationEvent) error {
			eventCh <- event
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
	event := waitForSupervisorTunnelConfigurationEvent(t, eventCh, 15*time.Second)
	if event.Reason != TunnelConfigurationEventInitial {
		t.Fatalf("unexpected event reason: %s", event.Reason)
	}
	for expectedIndex := range 2 {
		select {
		case actualIndex := <-addressIndexes:
			if actualIndex != expectedIndex {
				t.Fatalf("unexpected resolved address index: got %d, want %d", actualIndex, expectedIndex)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("resolved address index %d was not attempted", expectedIndex)
		}
	}
	err = tryEchoClientThroughServer(client, server, []byte("resolved-address-cursor"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
}

func TestClientSupervisorReconnectsTLSSessionAfterTCPDrop(t *testing.T) {
	t.Parallel()
	listenAddress := reserveListenAddressForProtocol(t, "tcp")

	firstServerContext, cancelFirstServerContext := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancelFirstServerContext()
	firstServer := startSupervisorTLSServer(t, firstServerContext, listenAddress)
	defer firstServer.Close()

	eventCh := make(chan TunnelConfigurationEvent, 4)
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
			eventCh <- event
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

	firstEvent := waitForSupervisorTunnelConfigurationEvent(t, eventCh, 10*time.Second)
	if firstEvent.Reason != TunnelConfigurationEventInitial {
		t.Fatalf("unexpected first event reason: %s", firstEvent.Reason)
	}
	err = tryEchoClientThroughServer(client, firstServer, []byte("before-reconnect"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	readResultCh := make(chan clientPacketReadResult, 1)
	go func() {
		packet, readErr := client.ReadDataPacket(context.Background())
		readResultCh <- clientPacketReadResult{
			packet: packet,
			err:    readErr,
		}
	}()

	err = firstServer.Close()
	if err != nil {
		t.Fatal(err)
	}

	secondServerContext, cancelSecondServerContext := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancelSecondServerContext()
	secondServer := startSupervisorTLSServer(t, secondServerContext, listenAddress)
	defer secondServer.Close()

	secondEvent := waitForSupervisorTunnelConfigurationEvent(t, eventCh, 20*time.Second)
	if secondEvent.Reason != TunnelConfigurationEventInitial {
		t.Fatalf("unexpected second event reason: %s", secondEvent.Reason)
	}

	reconnectedPayload := makeIPv4TestPacket("10.8.0.2", "10.8.0.1", []byte("after-reconnect"))
	err = client.WriteDataPacket(reconnectedPayload)
	if err != nil {
		t.Fatal(err)
	}
	serverReadContext, cancelServerRead := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelServerRead()
	serverPacket, err := secondServer.ReadDataPacket(serverReadContext)
	if err != nil {
		t.Fatal(err)
	}
	err = secondServer.WriteDataPacket(serverPacket.PeerAddress, serverPacket.Payload)
	if err != nil {
		t.Fatal(err)
	}
	readResult := waitForClientPacketReadResult(t, readResultCh, 5*time.Second)
	if readResult.err != nil {
		t.Fatal(readResult.err)
	}
	if !bytes.Equal(readResult.packet, reconnectedPayload) {
		t.Fatalf("unexpected reconnected payload: %q", readResult.packet)
	}
}

func TestClientTerminalAuthFailureUnblocksReadDataPacketBuffer(t *testing.T) {
	t.Parallel()
	listenAddress := reserveListenAddressForProtocol(t, "tcp")

	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelServerContext()
	server, err := NewServer(ServerOptions{
		Context:   serverContext,
		Mode:      ModeTLS,
		Transport: ServerTransportOptions{ListenAddress: listenAddress, Protocol: "tcp"},
		TLS: ServerTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Authentication: ServerAuthenticationOptions{Authenticator: func(_ context.Context, username string, password string) error {
			if username != "test-user" || password != "expected-password" {
				return ErrAuthenticationFailed
			}
			return nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}

	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 20*time.Second)
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
		Authentication: ClientAuthenticationOptions{Username: "test-user", Password: "wrong-password"},
		Pull:           ClientPullOptions{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	readErrCh := readClientBufferErrorAsync(client)
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}

	readErr := waitForClientReadError(t, readErrCh, 10*time.Second)
	if !E.IsMulti(readErr, ErrAuthenticationFailed) {
		t.Fatalf("expected authentication failure, got %v", readErr)
	}
}

func TestClientConstructionContextCancellationUnblocksReadDataPacketBuffer(t *testing.T) {
	t.Parallel()
	listenAddress := reserveListenAddressForProtocol(t, "tcp")

	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelServerContext()
	server := startSupervisorTLSServer(t, serverContext, listenAddress)
	defer server.Close()

	eventCh := make(chan TunnelConfigurationEvent, 4)
	clientContext, cancelClientContext := context.WithCancel(context.Background())
	client, err := NewClient(ClientOptions{
		Context:   clientContext,
		Mode:      ModeTLS,
		Transport: clientTransportOptions(t, listenAddress, "tcp"),
		TLS: ClientTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		OnTunnelConfiguration: func(event TunnelConfigurationEvent) error {
			eventCh <- event
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
	event := waitForSupervisorTunnelConfigurationEvent(t, eventCh, 10*time.Second)
	if event.Reason != TunnelConfigurationEventInitial {
		t.Fatalf("unexpected event reason: %s", event.Reason)
	}

	readErrCh := readClientBufferErrorAsync(client)
	cancelClientContext()

	readErr := waitForClientReadError(t, readErrCh, 10*time.Second)
	if !E.IsMulti(readErr, ErrClientClosed) {
		t.Fatalf("expected client closed, got %v", readErr)
	}
}

func TestClientCloseFromInitialTunnelConfigurationCallbackDoesNotDeadlock(t *testing.T) {
	t.Parallel()
	listenAddress := reserveListenAddressForProtocol(t, "tcp")

	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelServerContext()
	server := startSupervisorTLSServer(t, serverContext, listenAddress)
	defer server.Close()

	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelClientContext()
	closeErrCh := make(chan error, 1)
	var client *Client
	var err error
	client, err = NewClient(ClientOptions{
		Context:   clientContext,
		Mode:      ModeTLS,
		Transport: clientTransportOptions(t, listenAddress, "tcp"),
		TLS: ClientTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		OnTunnelConfiguration: func(event TunnelConfigurationEvent) error {
			if event.Reason != TunnelConfigurationEventInitial {
				return nil
			}
			closeErrCh <- client.Close()
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
	case closeErr := <-closeErrCh:
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Fatal(closeErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for callback close")
	}
}

func TestTLSServerCloseCancelsBlockingAuthenticator(t *testing.T) {
	t.Parallel()
	listenAddress := reserveListenAddressForProtocol(t, "tcp")
	authStarted := make(chan struct{}, 1)

	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelServerContext()
	server, err := NewServer(ServerOptions{
		Context:   serverContext,
		Mode:      ModeTLS,
		Transport: ServerTransportOptions{ListenAddress: listenAddress, Protocol: "tcp"},
		TLS: ServerTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Authentication: ServerAuthenticationOptions{Authenticator: func(ctx context.Context, username string, password string) error {
			_, _ = username, password
			select {
			case authStarted <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return ctx.Err()
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}

	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 20*time.Second)
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
		Authentication: ClientAuthenticationOptions{Username: "test-user", Password: "test-password"},
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
	case <-authStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for authenticator")
	}
	closeErrCh := make(chan error, 1)
	go func() {
		closeErrCh <- server.Close()
	}()
	select {
	case closeErr := <-closeErrCh:
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server close")
	}
}

func TestTLSServerReadDataPacketBufferUnblocksOnClose(t *testing.T) {
	t.Parallel()
	listenAddress := reserveListenAddressForProtocol(t, "tcp")

	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelServerContext()
	server := startSupervisorTLSServer(t, serverContext, listenAddress)
	readErrCh := make(chan error, 1)
	go func() {
		serverPacket, readErr := server.ReadDataPacketBuffer(context.Background())
		if serverPacket.Buffer != nil {
			serverPacket.Buffer.Release()
		}
		readErrCh <- readErr
	}()
	err := server.Close()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case readErr := <-readErrCh:
		if !E.IsMulti(readErr, ErrServerClosed) {
			t.Fatalf("expected server closed, got %v", readErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server read unblock")
	}
}

func startSupervisorTLSServer(t *testing.T, ctx context.Context, listenAddress string) *Server {
	t.Helper()
	server, err := NewServer(ServerOptions{
		Context:   ctx,
		Mode:      ModeTLS,
		Transport: ServerTransportOptions{ListenAddress: listenAddress, Protocol: "tcp"},
		TLS: ServerTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Tunnel: ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
			Topology:     "subnet",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func waitForSupervisorTunnelConfigurationEvent(t *testing.T, eventCh <-chan TunnelConfigurationEvent, timeout time.Duration) TunnelConfigurationEvent {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case event := <-eventCh:
		return event
	case <-timer.C:
		t.Fatal("timed out waiting for tunnel configuration event")
		return TunnelConfigurationEvent{}
	}
}

func tryEchoClientThroughServer(client *Client, server *Server, payload []byte, timeout time.Duration) error {
	payload = makeIPv4TestPacket("10.8.0.2", "10.8.0.1", payload)
	writeErr := client.WriteDataPacket(payload)
	if writeErr != nil {
		return writeErr
	}
	serverReadContext, cancelServerRead := context.WithTimeout(context.Background(), timeout)
	defer cancelServerRead()
	serverPacket, err := server.ReadDataPacket(serverReadContext)
	if err != nil {
		return E.Cause(err, "server read")
	}
	writeErr = server.WriteDataPacket(serverPacket.PeerAddress, serverPacket.Payload)
	if writeErr != nil {
		return writeErr
	}
	clientReadContext, cancelClientRead := context.WithTimeout(context.Background(), timeout)
	defer cancelClientRead()
	reply, err := client.ReadDataPacket(clientReadContext)
	if err != nil {
		return E.Cause(err, "client read")
	}
	if !bytes.Equal(reply, payload) {
		return E.New("unexpected reply payload")
	}
	return nil
}

type clientPacketReadResult struct {
	packet []byte
	err    error
}

func waitForClientPacketReadResult(t *testing.T, resultCh <-chan clientPacketReadResult, timeout time.Duration) clientPacketReadResult {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-resultCh:
		return result
	case <-timer.C:
		t.Fatal("timed out waiting for client packet read")
		return clientPacketReadResult{}
	}
}

func readClientBufferErrorAsync(client *Client) <-chan error {
	readErrCh := make(chan error, 1)
	go func() {
		packetBuffer, readErr := client.ReadDataPacketBuffer(context.Background())
		if packetBuffer != nil {
			packetBuffer.Release()
		}
		readErrCh <- readErr
	}()
	return readErrCh
}

func waitForClientReadError(t *testing.T, readErrCh <-chan error, timeout time.Duration) error {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case readErr := <-readErrCh:
		if readErr == nil {
			t.Fatal("expected read error, got nil")
		}
		return readErr
	case <-timer.C:
		t.Fatal("timed out waiting for client read error")
		return nil
	}
}
