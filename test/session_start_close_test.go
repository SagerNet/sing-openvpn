package test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/sagernet/sing-openvpn"
	E "github.com/sagernet/sing/common/exceptions"
)

type tlsStartupGateConn struct {
	net.Conn
	holdFirstClose bool

	readAccess       sync.Mutex
	readCount        int
	resetRead        chan struct{}
	releaseResetRead chan struct{}
	resetReadOnce    sync.Once
	releaseOnce      sync.Once
	closeObserved    chan struct{}
	closeObserveOnce sync.Once
	closeCount       atomic.Uint32
	closing          atomic.Bool
	writesAfterClose atomic.Uint32
}

func newTLSStartupGateConn(connection net.Conn, holdFirstClose bool) *tlsStartupGateConn {
	return &tlsStartupGateConn{
		Conn:             connection,
		holdFirstClose:   holdFirstClose,
		resetRead:        make(chan struct{}),
		releaseResetRead: make(chan struct{}),
		closeObserved:    make(chan struct{}),
	}
}

func (c *tlsStartupGateConn) Read(buffer []byte) (int, error) {
	c.readAccess.Lock()
	c.readCount++
	readCount := c.readCount
	c.readAccess.Unlock()
	if readCount > 2 {
		return c.Conn.Read(buffer)
	}
	readLength, err := io.ReadFull(c.Conn, buffer)
	if readCount == 2 && err == nil {
		c.resetReadOnce.Do(func() {
			close(c.resetRead)
		})
		<-c.releaseResetRead
	}
	return readLength, err
}

func (c *tlsStartupGateConn) Write(buffer []byte) (int, error) {
	if c.closing.Load() {
		c.writesAfterClose.Add(1)
	}
	return c.Conn.Write(buffer)
}

func (c *tlsStartupGateConn) Close() error {
	closeCount := c.closeCount.Add(1)
	c.closing.Store(true)
	c.closeObserveOnce.Do(func() {
		close(c.closeObserved)
	})
	if c.holdFirstClose && closeCount == 1 {
		return nil
	}
	return c.Conn.Close()
}

func (c *tlsStartupGateConn) release() {
	c.resetReadOnce.Do(func() {
		close(c.resetRead)
	})
	c.releaseOnce.Do(func() {
		close(c.releaseResetRead)
	})
}

type tlsStartupGateListener struct {
	net.Listener
	accepted chan *tlsStartupGateConn
}

func (l *tlsStartupGateListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	gatedConnection := newTLSStartupGateConn(connection, true)
	l.accepted <- gatedConnection
	return gatedConnection, nil
}

func TestTLSClientClosePreventsLateControlChannelStart(t *testing.T) {
	listenAddress := reserveListenAddressForProtocol(t, "tcp")
	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelServerContext()
	server := startSupervisorTLSServer(t, serverContext, listenAddress)
	defer server.Close()

	gatedConnectionCh := make(chan *tlsStartupGateConn, 1)
	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelClientContext()
	client, err := NewClient(ClientOptions{
		Context: clientContext,
		Mode:    ModeTLS,
		Transport: ClientTransportOptions{
			Remotes:  []Remote{clientRemote(t, listenAddress, "tcp")},
			Protocol: "tcp",
			DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
				connection, dialErr := (&net.Dialer{}).DialContext(ctx, network, address)
				if dialErr != nil {
					return nil, dialErr
				}
				gatedConnection := newTLSStartupGateConn(connection, false)
				gatedConnectionCh <- gatedConnection
				return gatedConnection, nil
			},
		},
		TLS: ClientTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Pull: ClientPullOptions{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}

	var gatedConnection *tlsStartupGateConn
	select {
	case gatedConnection = <-gatedConnectionCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the TLS transport")
	}
	defer gatedConnection.release()
	select {
	case <-gatedConnection.resetRead:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the server hard reset")
	}
	closeResult := make(chan error, 1)
	go func() {
		closeResult <- client.Close()
	}()
	select {
	case <-gatedConnection.closeObserved:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the client transport to close")
	}
	gatedConnection.release()
	select {
	case closeErr := <-closeResult:
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Fatal(closeErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Client.Close")
	}
	writeCount := gatedConnection.writesAfterClose.Load()
	if writeCount != 0 {
		t.Fatalf("TLS startup wrote %d packets after Client.Close", writeCount)
	}
}

func TestTLSClientContextCancellationPreventsLateControlChannelStart(t *testing.T) {
	listenAddress := reserveListenAddressForProtocol(t, "tcp")
	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelServerContext()
	server := startSupervisorTLSServer(t, serverContext, listenAddress)
	defer server.Close()

	gatedConnectionCh := make(chan *tlsStartupGateConn, 1)
	clientContext, cancelClientContext := context.WithCancel(context.Background())
	defer cancelClientContext()
	client, err := NewClient(ClientOptions{
		Context: clientContext,
		Mode:    ModeTLS,
		Transport: ClientTransportOptions{
			Remotes:  []Remote{clientRemote(t, listenAddress, "tcp")},
			Protocol: "tcp",
			DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
				connection, dialErr := (&net.Dialer{}).DialContext(ctx, network, address)
				if dialErr != nil {
					return nil, dialErr
				}
				gatedConnection := newTLSStartupGateConn(connection, false)
				gatedConnectionCh <- gatedConnection
				return gatedConnection, nil
			},
		},
		TLS: ClientTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Pull: ClientPullOptions{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}

	var gatedConnection *tlsStartupGateConn
	select {
	case gatedConnection = <-gatedConnectionCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the TLS transport")
	}
	defer gatedConnection.release()
	select {
	case <-gatedConnection.resetRead:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the server hard reset")
	}
	readErrCh := readClientBufferErrorAsync(client)
	cancelClientContext()
	select {
	case <-gatedConnection.closeObserved:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for context cancellation to close the TLS transport")
	}
	gatedConnection.release()
	readErr := waitForClientReadError(t, readErrCh, 5*time.Second)
	if !E.IsMulti(readErr, ErrClientClosed) {
		t.Fatalf("expected client closed after context cancellation, got %v", readErr)
	}
	writeCount := gatedConnection.writesAfterClose.Load()
	if writeCount != 0 {
		t.Fatalf("TLS startup wrote %d packets after context cancellation", writeCount)
	}
}

func TestTLSClientCloseRacesSessionPublication(t *testing.T) {
	listenAddress := reserveListenAddressForProtocol(t, "tcp")
	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelServerContext()
	server := startSupervisorTLSServer(t, serverContext, listenAddress)
	defer server.Close()

	for iteration := 0; iteration < 100; iteration++ {
		dialReady := make(chan struct{})
		releaseDial := make(chan struct{})
		clientContext, cancelClientContext := context.WithTimeout(context.Background(), 10*time.Second)
		client, err := NewClient(ClientOptions{
			Context: clientContext,
			Mode:    ModeTLS,
			Transport: ClientTransportOptions{
				Remotes:  []Remote{clientRemote(t, listenAddress, "tcp")},
				Protocol: "tcp",
				DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
					connection, dialErr := (&net.Dialer{}).DialContext(ctx, network, address)
					if dialErr != nil {
						return nil, dialErr
					}
					close(dialReady)
					<-releaseDial
					return connection, nil
				},
			},
			TLS: ClientTLSOptions{
				CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
				Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
				Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
			},
			Pull: ClientPullOptions{Enabled: true},
		})
		if err != nil {
			cancelClientContext()
			t.Fatal(err)
		}
		err = client.Start()
		if err != nil {
			cancelClientContext()
			t.Fatal(err)
		}
		select {
		case <-dialReady:
		case <-time.After(5 * time.Second):
			cancelClientContext()
			_ = client.Close()
			t.Fatal("timed out waiting for the initialized transport")
		}
		raceStart := make(chan struct{})
		closeResult := make(chan error, 1)
		go func() {
			<-raceStart
			close(releaseDial)
		}()
		go func() {
			<-raceStart
			closeResult <- client.Close()
		}()
		close(raceStart)
		select {
		case closeErr := <-closeResult:
			if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
				cancelClientContext()
				t.Fatal(closeErr)
			}
		case <-time.After(5 * time.Second):
			cancelClientContext()
			_ = server.Close()
			t.Fatalf("Client.Close blocked while publishing TLS session %d", iteration)
		}
		cancelClientContext()
	}
}

func TestTLSServerClosePreventsLateControlChannelStart(t *testing.T) {
	rawListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gatedListener := &tlsStartupGateListener{
		Listener: rawListener,
		accepted: make(chan *tlsStartupGateConn, 1),
	}
	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelServerContext()
	server, err := NewServer(ServerOptions{
		Context:   serverContext,
		Mode:      ModeTLS,
		Transport: ServerTransportOptions{Listener: gatedListener, Protocol: "tcp"},
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
		Transport: clientTransportOptions(t, rawListener.Addr().String(), "tcp"),
		TLS: ClientTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Pull: ClientPullOptions{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}

	var gatedConnection *tlsStartupGateConn
	select {
	case gatedConnection = <-gatedListener.accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the accepted TLS transport")
	}
	defer func() {
		gatedConnection.release()
		_ = gatedConnection.Conn.Close()
	}()
	select {
	case <-gatedConnection.resetRead:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the client hard reset")
	}
	closeResult := make(chan error, 1)
	go func() {
		closeResult <- server.Close()
	}()
	select {
	case <-gatedConnection.closeObserved:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the server session to close")
	}
	gatedConnection.release()
	select {
	case closeErr := <-closeResult:
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Server.Close")
	}
	writeCount := gatedConnection.writesAfterClose.Load()
	if writeCount > 1 {
		t.Fatalf("server wrote %d packets after close request; only the pending hard reset is allowed", writeCount)
	}
}
