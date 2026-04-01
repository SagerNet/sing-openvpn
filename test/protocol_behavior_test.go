package test

import (
	"bytes"
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	. "github.com/sagernet/sing-openvpn"
)

func TestMissingProtocolBehavior_AddressPoolAssignsClientIPv4Address(t *testing.T) {
	listenAddress := reserveListenAddressForProtocol(t, "udp")
	server, err := NewServer(ServerOptions{
		Context:   context.Background(),
		Mode:      ModeTLS,
		Transport: ServerTransportOptions{ListenAddress: listenAddress, Protocol: "udp"},
		TLS: ServerTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Tunnel: ServerTunnelOptions{
			Topology:     "subnet",
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
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
	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 5*time.Second)
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
	waitForClientReady(t, client, 5*time.Second)
	configuration := waitForClientIfconfig(t, client, 2*time.Second)
	if len(configuration.LocalIPv4) != 1 || configuration.LocalIPv4[0] != netip.MustParsePrefix("10.8.0.2/24") {
		t.Fatalf("expected ifconfig-pool assignment, got %+v", configuration.LocalIPv4)
	}
	serverToClientPacket := makeIPv4TestPacket("10.8.0.1", "10.8.0.2", []byte("assigned-ipv4"))
	err = server.WriteDataPacketByDestination(serverToClientPacket)
	if err != nil {
		t.Fatal(err)
	}
	readContext, cancelRead := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelRead()
	clientPacket, err := client.ReadDataPacket(readContext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientPacket, serverToClientPacket) {
		t.Fatalf("unexpected routed packet: %x", clientPacket)
	}
}

func TestMissingProtocolBehavior_AddressPoolAssignsClientIPv6Address(t *testing.T) {
	listenAddress := reserveListenAddressForProtocol(t, "udp")
	server, err := NewServer(ServerOptions{
		Context:   context.Background(),
		Mode:      ModeTLS,
		Transport: ServerTransportOptions{ListenAddress: listenAddress, Protocol: "udp"},
		TLS: ServerTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Tunnel: ServerTunnelOptions{AddressPools: []netip.Prefix{netip.MustParsePrefix("fd00::/64")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}
	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 5*time.Second)
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
	waitForClientReady(t, client, 5*time.Second)
	var configuration TunnelConfiguration
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		configuration = client.TunnelConfiguration()
		if len(configuration.LocalIPv6) > 0 {
			if len(configuration.LocalIPv6) != 1 || configuration.LocalIPv6[0] != netip.MustParsePrefix("fd00::2/64") {
				t.Fatalf("expected ifconfig-ipv6-pool assignment, got %+v", configuration.LocalIPv6)
			}
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(configuration.LocalIPv6) == 0 {
		t.Fatal("expected ifconfig-ipv6-pool assignment")
	}
	serverToClientPacket := buildIPv6TestPacket(t, "fd00::1", "fd00::2", []byte("assigned-ipv6"))
	err = server.WriteDataPacketByDestination(serverToClientPacket)
	if err != nil {
		t.Fatal(err)
	}
	readContext, cancelRead := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelRead()
	clientPacket, err := client.ReadDataPacket(readContext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientPacket, serverToClientPacket) {
		t.Fatalf("unexpected routed packet: %x", clientPacket)
	}
}
