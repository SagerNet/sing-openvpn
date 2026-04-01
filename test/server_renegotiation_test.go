package test

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	. "github.com/sagernet/sing-openvpn"
)

type observedAuthCredentials struct {
	username string
	password string
}

func TestTLSServerInitiatedRenegotiationKeepsDataFlowing(t *testing.T) {
	listenAddress := reserveListenAddressForProtocol(t, "udp")
	credentialEvents := make(chan observedAuthCredentials, 8)

	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancelServerContext()
	renegotiationInterval := 2 * time.Second
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
		Timing: ServerTimingOptions{RenegotiationInterval: renegotiationInterval},
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

	err = tryEchoClientThroughServer(client, server, []byte("pre-reneg"), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	driveEchoUntilObservedCredentials(t, client, server, credentialEvents, "test-user", "test-password", 60*time.Second)
	err = tryEchoClientThroughServer(client, server, []byte("post-reneg"), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
}

func driveEchoUntilObservedCredentials(
	t *testing.T,
	client *Client,
	server *Server,
	credentialEvents <-chan observedAuthCredentials,
	expectedUsername string,
	expectedPassword string,
	timeout time.Duration,
) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case credentials := <-credentialEvents:
			if credentials.username == expectedUsername && credentials.password == expectedPassword {
				return
			}
		default:
		}
		err := tryEchoClientThroughServer(client, server, []byte("drive-reneg"), 2*time.Second)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
	}
	t.Fatalf("timed out waiting for observed credentials username=%q password=%q", expectedUsername, expectedPassword)
}

func waitForObservedCredentials(t *testing.T, credentialEvents <-chan observedAuthCredentials, expectedUsername string, expectedPassword string, timeout time.Duration) {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case credentials := <-credentialEvents:
			if credentials.username == expectedUsername && credentials.password == expectedPassword {
				return
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for observed credentials username=%q password=%q", expectedUsername, expectedPassword)
		}
	}
}
