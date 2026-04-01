package test

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/sagernet/sing-openvpn"
	E "github.com/sagernet/sing/common/exceptions"
)

func TestTLSLoopbackDataPlaneRoutesByDestination(t *testing.T) {
	listenAddress := reserveListenAddressForProtocol(t, "tcp")
	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelServerContext()
	server, err := NewServer(ServerOptions{
		Context:     serverContext,
		Mode:        ModeTLS,
		Transport:   ServerTransportOptions{ListenAddress: listenAddress, Protocol: "tcp"},
		DataChannel: ServerDataChannelOptions{MTU: 1400, PacketHeadroom: 32},
		TLS: ServerTLSOptions{
			CertificateAuthority: Material{Content: localFixtureContent(t, "ca.crt")},
			Certificate:          Material{Content: localFixtureContent(t, "server.crt")},
			Key:                  Material{Content: localFixtureContent(t, "server.key")},
			CryptV2:              Material{Content: localFixtureContent(t, "tls-crypt-v2-server.key")},
		},
		Tunnel: ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
			Topology:     "subnet",
		},
		Push: ServerPushOptions{
			Routes: []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")},
			DNS:    []netip.Addr{netip.MustParseAddr("1.1.1.1")},
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

	eventCh := make(chan TunnelConfigurationEvent, 4)
	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelClientContext()
	client, err := NewClient(ClientOptions{
		Context:     clientContext,
		Mode:        ModeTLS,
		Transport:   clientTransportOptions(t, listenAddress, "tcp"),
		DataChannel: ClientDataChannelOptions{PacketHeadroom: 32},
		TLS: ClientTLSOptions{
			CertificateAuthority: Material{Content: localFixtureContent(t, "ca.crt")},
			Certificate:          Material{Content: localFixtureContent(t, "client.crt")},
			Key:                  Material{Content: localFixtureContent(t, "client.key")},
			CryptV2:              Material{Content: localFixtureContent(t, "tls-crypt-v2-client.key")},
		},
		Pull: ClientPullOptions{
			Enabled: true,
			Filters: []PullFilter{{Action: "reject", Text: "dns "}},
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
	waitForClientReady(t, client, 5*time.Second)
	event := receiveTunnelConfigurationEvent(t, eventCh)
	if event.Reason != TunnelConfigurationEventInitial {
		t.Fatalf("unexpected event reason: %s", event.Reason)
	}
	if event.Configuration.TunMTU != 1400 {
		t.Fatalf("unexpected mtu: %d", event.Configuration.TunMTU)
	}
	if len(event.Configuration.LocalIPv4) != 1 || event.Configuration.LocalIPv4[0] != netip.MustParsePrefix("10.8.0.2/24") {
		t.Fatalf("unexpected local ipv4 prefixes: %+v", event.Configuration.LocalIPv4)
	}
	if len(event.Configuration.IPv4Routes) != 1 || event.Configuration.IPv4Routes[0].Prefix != netip.MustParsePrefix("10.9.0.0/24") {
		t.Fatalf("unexpected ipv4 routes: %+v", event.Configuration.IPv4Routes)
	}
	if len(event.Configuration.DNS) != 1 || event.Configuration.DNS[0] != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("unexpected dns: %+v", event.Configuration.DNS)
	}
	if len(event.Configuration.DHCPOptions) != 1 || event.Configuration.DHCPOptions[0] != "DNS 1.1.1.1" {
		t.Fatalf("unexpected dhcp options: %+v", event.Configuration.DHCPOptions)
	}

	clientToServerPacket := makeIPv4TestPacket("10.8.0.2", "10.8.0.1", []byte("client-to-server"))
	err = client.WriteDataPacket(clientToServerPacket)
	if err != nil {
		t.Fatal(err)
	}
	serverReadContext, cancelServerRead := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelServerRead()
	serverPacket, err := server.ReadDataPacketBuffer(serverReadContext)
	if err != nil {
		t.Fatal(err)
	}
	if serverPacket.Buffer.Start() != 32 {
		t.Fatalf("unexpected server headroom: %d", serverPacket.Buffer.Start())
	}
	if !bytes.Equal(serverPacket.Buffer.Bytes(), clientToServerPacket) {
		t.Fatalf("unexpected server packet: %x", serverPacket.Buffer.Bytes())
	}
	if len(serverPacket.Buffer.ExtendHeader(16)) != 16 {
		t.Fatal("server headroom is not writable")
	}

	serverToClientPacket := makeIPv4TestPacket("10.8.0.1", "10.8.0.2", []byte("server-to-client"))
	err = server.WriteDataPacketByDestination(serverToClientPacket)
	if err != nil {
		t.Fatal(err)
	}
	clientReadContext, cancelClientRead := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelClientRead()
	clientPacket, err := client.ReadDataPacketBuffer(clientReadContext)
	if err != nil {
		t.Fatal(err)
	}
	if clientPacket.Start() != 32 {
		t.Fatalf("unexpected client headroom: %d", clientPacket.Start())
	}
	if !bytes.Equal(clientPacket.Bytes(), serverToClientPacket) {
		t.Fatalf("unexpected client packet: %x", clientPacket.Bytes())
	}
	if len(clientPacket.ExtendHeader(16)) != 16 {
		t.Fatal("client headroom is not writable")
	}

	missPacket := makeIPv4TestPacket("10.8.0.1", "10.8.0.99", []byte("miss"))
	err = server.WriteDataPacketByDestination(missPacket)
	missErr, routeMiss := E.Cast[*RouteMissError](err)
	if !routeMiss {
		t.Fatalf("expected route miss, got %v", err)
	}
	if missErr.Destination != netip.MustParseAddr("10.8.0.99") {
		t.Fatalf("unexpected miss destination: %s", missErr.Destination)
	}
	if !bytes.Equal(missErr.Packet, missPacket) {
		t.Fatal("route miss did not preserve packet")
	}
}

func TestTLSLoopbackPushDNSEmitsDHCPOptionAndPromotesTypedDNS(t *testing.T) {
	listenAddress := reserveListenAddressForProtocol(t, "tcp")
	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelServerContext()
	server, err := NewServer(ServerOptions{
		Context:   serverContext,
		Mode:      ModeTLS,
		Transport: ServerTransportOptions{ListenAddress: listenAddress, Protocol: "tcp"},
		TLS: ServerTLSOptions{
			CertificateAuthority: Material{Content: localFixtureContent(t, "ca.crt")},
			Certificate:          Material{Content: localFixtureContent(t, "server.crt")},
			Key:                  Material{Content: localFixtureContent(t, "server.key")},
			CryptV2:              Material{Content: localFixtureContent(t, "tls-crypt-v2-server.key")},
		},
		Tunnel: ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
		},
		Push: ServerPushOptions{
			DNS: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2001:4860:4860::8888")},
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

	eventCh := make(chan TunnelConfigurationEvent, 4)
	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelClientContext()
	client, err := NewClient(ClientOptions{
		Context:   clientContext,
		Mode:      ModeTLS,
		Transport: clientTransportOptions(t, listenAddress, "tcp"),
		TLS: ClientTLSOptions{
			CertificateAuthority: Material{Content: localFixtureContent(t, "ca.crt")},
			Certificate:          Material{Content: localFixtureContent(t, "client.crt")},
			Key:                  Material{Content: localFixtureContent(t, "client.key")},
			CryptV2:              Material{Content: localFixtureContent(t, "tls-crypt-v2-client.key")},
		},
		Pull: ClientPullOptions{
			Enabled: true,
			Filters: []PullFilter{{Action: "reject", Text: "dns "}},
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
	waitForClientReady(t, client, 5*time.Second)
	event := receiveTunnelConfigurationEvent(t, eventCh)
	if event.Reason != TunnelConfigurationEventInitial {
		t.Fatalf("unexpected event reason: %s", event.Reason)
	}
	configuration := client.TunnelConfiguration()
	expectedDNS := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2001:4860:4860::8888")}
	if len(configuration.DNS) != len(expectedDNS) {
		t.Fatalf("unexpected dns: %+v", configuration.DNS)
	}
	for index, expectedAddress := range expectedDNS {
		if configuration.DNS[index] != expectedAddress {
			t.Fatalf("unexpected dns: %+v", configuration.DNS)
		}
	}
	expectedDHCPOptions := []string{"DNS 1.1.1.1", "DNS6 2001:4860:4860::8888"}
	if len(configuration.DHCPOptions) != len(expectedDHCPOptions) {
		t.Fatalf("unexpected dhcp options: %+v", configuration.DHCPOptions)
	}
	for index, expectedOption := range expectedDHCPOptions {
		if configuration.DHCPOptions[index] != expectedOption {
			t.Fatalf("unexpected dhcp options: %+v", configuration.DHCPOptions)
		}
	}
}

func TestServerUDPTransportInjectionAndAuthenticator(t *testing.T) {
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	authCalls := make(chan [2]string, 1)
	server, err := NewServer(ServerOptions{
		Context:   context.Background(),
		Mode:      ModeTLS,
		Transport: ServerTransportOptions{PacketConn: packetConn, Protocol: "udp"},
		TLS: ServerTLSOptions{
			CertificateAuthority: Material{Content: localFixtureContent(t, "ca.crt")},
			Certificate:          Material{Content: localFixtureContent(t, "server.crt")},
			Key:                  Material{Content: localFixtureContent(t, "server.key")},
		},
		Authentication: ServerAuthenticationOptions{Authenticator: func(ctx context.Context, username string, password string) error {
			_ = ctx
			authCalls <- [2]string{username, password}
			if username == "user-a" && password == "pass-a" {
				return nil
			}
			return ErrAuthenticationFailed
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
	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelClientContext()
	client, err := NewClient(ClientOptions{
		Context:   clientContext,
		Mode:      ModeTLS,
		Transport: clientTransportOptions(t, packetConn.LocalAddr().String(), "udp"),
		TLS: ClientTLSOptions{
			CertificateAuthority: Material{Content: localFixtureContent(t, "ca.crt")},
			Certificate:          Material{Content: localFixtureContent(t, "client.crt")},
			Key:                  Material{Content: localFixtureContent(t, "client.key")},
		},
		Authentication: ClientAuthenticationOptions{Username: "user-a", Password: "pass-a"},
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
	select {
	case credentials := <-authCalls:
		if credentials != [2]string{"user-a", "pass-a"} {
			t.Fatalf("unexpected credentials: %+v", credentials)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("authenticator was not called")
	}
}

func receiveTunnelConfigurationEvent(t *testing.T, eventCh <-chan TunnelConfigurationEvent) TunnelConfigurationEvent {
	t.Helper()
	select {
	case event := <-eventCh:
		return event
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for tunnel configuration event")
		return TunnelConfigurationEvent{}
	}
}

func makeIPv4TestPacket(source string, destination string, payload []byte) []byte {
	sourceAddress := netip.MustParseAddr(source).As4()
	destinationAddress := netip.MustParseAddr(destination).As4()
	totalLength := 20 + len(payload)
	packet := make([]byte, totalLength)
	packet[0] = 0x45
	packet[2] = byte(totalLength >> 8)
	packet[3] = byte(totalLength)
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], sourceAddress[:])
	copy(packet[16:20], destinationAddress[:])
	copy(packet[20:], payload)
	return packet
}

func buildIPv6TestPacket(t *testing.T, source string, destination string, payload []byte) []byte {
	t.Helper()
	sourceAddress := netip.MustParseAddr(source).As16()
	destinationAddress := netip.MustParseAddr(destination).As16()
	totalLength := 40 + len(payload)
	packet := make([]byte, totalLength)
	packet[0] = 0x60
	packet[4] = byte(len(payload) >> 8)
	packet[5] = byte(len(payload))
	packet[6] = 17
	packet[7] = 64
	copy(packet[8:24], sourceAddress[:])
	copy(packet[24:40], destinationAddress[:])
	copy(packet[40:], payload)
	return packet
}

func localFixtureContent(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", "openvpn", "pki", name))
	if err != nil {
		t.Fatal(err)
	}
	return content
}
