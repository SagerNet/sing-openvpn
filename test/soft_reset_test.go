package test

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	. "github.com/sagernet/sing-openvpn"
)

func TestTLSClientInitiatedRenegotiationKeepsDataFlowing(t *testing.T) {
	listenAddress := reserveListenAddressForProtocol(t, "udp")
	credentialEvents := make(chan observedAuthCredentials, 8)

	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancelServerContext()
	server, err := NewServer(ServerOptions{
		Context:   serverContext,
		Mode:      ModeTLS,
		Transport: ServerTransportOptions{ListenAddress: listenAddress, Protocol: "udp"},
		TLS: ServerTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Authentication: ServerAuthenticationOptions{Authenticator: func(_ context.Context, username string, password string) error {
			select {
			case credentialEvents <- observedAuthCredentials{username: username, password: password}:
			default:
			}
			if username == "test-user" && password == "test-password" {
				return nil
			}
			return ErrAuthenticationFailed
		}},
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

	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancelClientContext()
	client, err := NewClient(ClientOptions{
		Context:   clientContext,
		Mode:      ModeTLS,
		Transport: clientTransportOptions(t, listenAddress, "udp"),
		TLS: ClientTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Authentication: ClientAuthenticationOptions{Username: "test-user", Password: "test-password"},
		Pull:           ClientPullOptions{Enabled: true},
		Timing:         ClientTimingOptions{RenegotiationPackets: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	waitForClientReady(t, client, 10*time.Second)
	waitForObservedCredentials(t, credentialEvents, "test-user", "test-password", 10*time.Second)

	err = tryEchoClientThroughServer(client, server, []byte("pre-client-reneg"), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	driveEchoUntilObservedCredentials(t, client, server, credentialEvents, "test-user", "test-password", 60*time.Second)
	err = tryEchoClientThroughServer(client, server, []byte("post-client-reneg"), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
}
