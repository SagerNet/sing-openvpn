package test

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/sagernet/sing-openvpn"
)

type blackholeWriteConnection struct {
	net.Conn
	dropWrites atomic.Bool
	readCount  atomic.Uint32
}

func (c *blackholeWriteConnection) Read(payload []byte) (int, error) {
	readBytes, err := c.Conn.Read(payload)
	if readBytes > 0 && c.dropWrites.Load() {
		c.readCount.Add(1)
	}
	return readBytes, err
}

func (c *blackholeWriteConnection) Write(payload []byte) (int, error) {
	if c.dropWrites.Load() {
		return len(payload), nil
	}
	return c.Conn.Write(payload)
}

func TestTLSServerPingMaintainsAndReclaimsUDPSession(t *testing.T) {
	listenAddress := reserveListenAddressForProtocol(t, "udp")
	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelServerContext()
	server, err := NewServer(ServerOptions{
		Context:   serverContext,
		Mode:      ModeTLS,
		Transport: ServerTransportOptions{ListenAddress: listenAddress, Protocol: "udp"},
		Resources: ServerResourceOptions{MaxClients: 1},
		TLS: ServerTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Timing: ServerTimingOptions{
			PingInterval: time.Second,
			PingRestart:  8 * time.Second,
		},
		Tunnel: ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/29")},
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

	firstTransport := clientTransportOptions(t, listenAddress, "udp")
	var dialCount atomic.Uint32
	var firstConnection atomic.Pointer[blackholeWriteConnection]
	firstTransport.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		if dialCount.Add(1) > 1 {
			return nil, ErrRemoteAddressExhausted
		}
		connection, dialErr := (&net.Dialer{}).DialContext(ctx, network, address)
		if dialErr != nil {
			return nil, dialErr
		}
		wrappedConnection := &blackholeWriteConnection{Conn: connection}
		firstConnection.Store(wrappedConnection)
		return wrappedConnection, nil
	}
	firstClientContext, cancelFirstClientContext := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelFirstClientContext()
	firstClient, err := NewClient(ClientOptions{
		Context:   firstClientContext,
		Mode:      ModeTLS,
		Transport: firstTransport,
		TLS: ClientTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Pull: ClientPullOptions{Enabled: true},
		Timing: ClientTimingOptions{
			PingInterval: time.Second,
			PingRestart:  5 * time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer firstClient.Close()
	err = firstClient.Start()
	if err != nil {
		t.Fatal(err)
	}
	waitForClientReady(t, firstClient, 10*time.Second)
	blackholedConnection := firstConnection.Load()
	if blackholedConnection == nil {
		t.Fatal("first client connection was not captured")
	}
	blackholedConnection.dropWrites.Store(true)

	time.Sleep(5500 * time.Millisecond)
	if !firstClient.Ready() {
		t.Fatalf("client lost readiness while server pings should keep it alive: reads=%d dials=%d", blackholedConnection.readCount.Load(), dialCount.Load())
	}
	time.Sleep(4500 * time.Millisecond)

	secondClientContext, cancelSecondClientContext := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelSecondClientContext()
	secondClient, err := NewClient(ClientOptions{
		Context:   secondClientContext,
		Mode:      ModeTLS,
		Transport: clientTransportOptions(t, listenAddress, "udp"),
		TLS: ClientTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Pull: ClientPullOptions{Enabled: true},
		Timing: ClientTimingOptions{
			PingInterval: time.Second,
			PingRestart:  5 * time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer secondClient.Close()
	err = secondClient.Start()
	if err != nil {
		t.Fatal(err)
	}
	waitForClientReady(t, secondClient, 10*time.Second)
}
