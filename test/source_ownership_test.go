package test

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	. "github.com/sagernet/sing-openvpn"
)

func TestTLSServerRejectsUnownedTunnelSources(t *testing.T) {
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
		Tunnel: ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24"), netip.MustParsePrefix("fd00::/64")},
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

	firstClient, firstConfiguration := startSourceOwnershipClient(t, listenAddress)
	defer firstClient.Close()
	secondClient, secondConfiguration := startSourceOwnershipClient(t, listenAddress)
	defer secondClient.Close()

	firstIPv4 := firstConfiguration.LocalIPv4[0].Addr()
	secondIPv4 := secondConfiguration.LocalIPv4[0].Addr()
	firstIPv6 := firstConfiguration.LocalIPv6[0].Addr()
	secondIPv6 := secondConfiguration.LocalIPv6[0].Addr()
	if firstIPv4 == secondIPv4 || firstIPv6 == secondIPv6 {
		t.Fatalf("clients received duplicate tunnel addresses: %s/%s and %s/%s", firstIPv4, firstIPv6, secondIPv4, secondIPv6)
	}

	validIPv4 := makeIPv4TestPacket(firstIPv4.String(), "10.8.0.1", []byte("owned-v4"))
	assertSourceOwnershipPacketDelivered(t, server, firstClient, validIPv4)
	validIPv6 := buildIPv6TestPacket(t, firstIPv6.String(), "fd00::1", []byte("owned-v6"))
	assertSourceOwnershipPacketDelivered(t, server, firstClient, validIPv6)

	testCases := []struct {
		name   string
		packet []byte
	}{
		{
			name:   "another client IPv4 source",
			packet: makeIPv4TestPacket(secondIPv4.String(), "10.8.0.1", []byte("spoofed-v4")),
		},
		{
			name:   "unassigned IPv4 source",
			packet: makeIPv4TestPacket("10.8.0.99", "10.8.0.1", []byte("unassigned-v4")),
		},
		{
			name:   "another client IPv6 source",
			packet: buildIPv6TestPacket(t, secondIPv6.String(), "fd00::1", []byte("spoofed-v6")),
		},
		{
			name:   "unassigned IPv6 source",
			packet: buildIPv6TestPacket(t, "fd00::99", "fd00::1", []byte("unassigned-v6")),
		},
		{
			name:   "malformed IP packet",
			packet: []byte{0x45, 0, 0, 20},
		},
		{
			name:   "IPv6 link-local source",
			packet: buildIPv6TestPacket(t, "fe80::2", "fd00::1", []byte("link-local-v6")),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(caseTest *testing.T) {
			assertSourceOwnershipPacketDropped(caseTest, server, firstClient, testCase.packet)
		})
	}
}

func startSourceOwnershipClient(t *testing.T, serverAddress string) (*Client, TunnelConfiguration) {
	t.Helper()
	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancelClientContext)
	client, err := NewClient(ClientOptions{
		Context:   clientContext,
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
	if len(configuration.LocalIPv4) != 1 || len(configuration.LocalIPv6) != 1 {
		_ = client.Close()
		t.Fatalf("expected dual-stack tunnel assignment, got IPv4=%+v IPv6=%+v", configuration.LocalIPv4, configuration.LocalIPv6)
	}
	return client, configuration
}

func assertSourceOwnershipPacketDelivered(t *testing.T, server *Server, client *Client, packet []byte) {
	t.Helper()
	err := client.WriteDataPacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	readContext, cancelRead := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelRead()
	packetBuffer, err := server.ReadDataPacketBuffer(readContext)
	if err != nil {
		t.Fatal(err)
	}
	defer packetBuffer.Buffer.Release()
	if !bytes.Equal(packetBuffer.Buffer.Bytes(), packet) {
		t.Fatalf("unexpected delivered packet: %x", packetBuffer.Buffer.Bytes())
	}
}

func assertSourceOwnershipPacketDropped(t *testing.T, server *Server, client *Client, packet []byte) {
	t.Helper()
	err := client.WriteDataPacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	readContext, cancelRead := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancelRead()
	packetBuffer, err := server.ReadDataPacketBuffer(readContext)
	if packetBuffer.Buffer != nil {
		packetBuffer.Buffer.Release()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unowned source packet was delivered or returned unexpected error: %v", err)
	}
}
