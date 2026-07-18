package test

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	. "github.com/sagernet/sing-openvpn"
)

func TestTLSServerDuplicateCNReplacementKeepsTunnelAddress(t *testing.T) {
	listenAddress := reserveListenAddressForProtocol(t, "tcp")
	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 30*time.Second)
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

	firstContext, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	firstClient, firstConfiguration := startDuplicateCNClient(t, firstContext, listenAddress)
	defer firstClient.Close()
	err = tryEchoClientThroughServer(firstClient, server, []byte("first-session"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	secondContext, cancelSecond := context.WithCancel(context.Background())
	defer cancelSecond()
	secondClient, secondConfiguration := startDuplicateCNClient(t, secondContext, listenAddress)
	defer secondClient.Close()
	cancelFirst()

	firstAddress := firstConfiguration.LocalIPv4[0]
	secondAddress := secondConfiguration.LocalIPv4[0]
	if secondAddress != firstAddress {
		t.Fatalf("replacement changed the sticky tunnel address: first=%s second=%s", firstAddress, secondAddress)
	}
	err = tryEchoClientThroughServer(secondClient, server, []byte("replacement-session"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
}

func startDuplicateCNClient(t *testing.T, ctx context.Context, serverAddress string) (*Client, TunnelConfiguration) {
	t.Helper()
	client, err := NewClient(ClientOptions{
		Context:   ctx,
		Mode:      ModeTLS,
		Transport: clientTransportOptions(t, serverAddress, "tcp"),
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
	err = client.Start()
	if err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	waitForClientReady(t, client, 5*time.Second)
	configuration := waitForClientIfconfig(t, client, 5*time.Second)
	if len(configuration.LocalIPv4) != 1 {
		_ = client.Close()
		t.Fatalf("expected one IPv4 tunnel address, got %+v", configuration.LocalIPv4)
	}
	return client, configuration
}
