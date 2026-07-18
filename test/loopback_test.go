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

type loopbackScenario struct {
	name                string
	protocol            string
	serverOptions       ServerOptions
	clientOptions       ClientOptions
	payload             []byte
	verifyConfiguration func(t *testing.T, configuration TunnelConfiguration)
}

func TestClientServerLoopbackIntegration(t *testing.T) {
	t.Parallel()
	testCases := []loopbackScenario{
		{
			name:     "tls_udp",
			protocol: "udp",
			payload:  []byte("loopback-tls-udp"),
		},
		{
			name:     "tls_tcp",
			protocol: "tcp",
			payload:  []byte("loopback-tls-tcp"),
		},
		{
			name:     "tls_udp_auth_user_pass",
			protocol: "udp",
			serverOptions: ServerOptions{
				Authentication: ServerAuthenticationOptions{
					Authenticator: func(_ context.Context, username string, password string) error {
						if username != "test-user" || password != "test-password" {
							return ErrAuthenticationFailed
						}
						return nil
					},
				},
			},
			clientOptions: ClientOptions{
				Authentication: ClientAuthenticationOptions{
					Username: "test-user",
					Password: "test-password",
				},
			},
			payload: []byte("loopback-auth"),
		},
		{
			name:     "tls_udp_tls_auth",
			protocol: "udp",
			serverOptions: ServerOptions{
				TLS:          ServerTLSOptions{Auth: Material{Content: []byte(testHexStaticKey())}},
				KeyDirection: 0,
			},
			clientOptions: ClientOptions{
				TLS:          ClientTLSOptions{Auth: Material{Content: []byte(testHexStaticKey())}},
				KeyDirection: 1,
			},
			payload: []byte("loopback-tls-auth"),
		},
		{
			name:     "tls_udp_tls_crypt",
			protocol: "udp",
			serverOptions: ServerOptions{
				TLS: ServerTLSOptions{Crypt: Material{Content: []byte(testHexStaticKey())}},
			},
			clientOptions: ClientOptions{
				TLS: ClientTLSOptions{Crypt: Material{Content: []byte(testHexStaticKey())}},
			},
			payload: []byte("loopback-tls-crypt"),
		},
		{
			name:     "tls_udp_tls_crypt_v2",
			protocol: "udp",
			serverOptions: ServerOptions{
				TLS: ServerTLSOptions{CryptV2: Material{Path: filepath.Join("testdata", "openvpn", "pki", "tls-crypt-v2-server.key")}},
			},
			clientOptions: ClientOptions{
				TLS: ClientTLSOptions{CryptV2: Material{Path: filepath.Join("testdata", "openvpn", "pki", "tls-crypt-v2-client.key")}},
			},
			payload: []byte("loopback-tls-crypt-v2"),
		},
		{
			name:     "tls_udp_push_basic",
			protocol: "udp",
			serverOptions: ServerOptions{
				DataChannel: ServerDataChannelOptions{MTU: 1412},
				Tunnel:      ServerTunnelOptions{Topology: "subnet"},
				Push: ServerPushOptions{
					Routes:          []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24"), netip.MustParsePrefix("fd10::/64")},
					DNS:             []netip.Addr{netip.MustParseAddr("1.1.1.1")},
					RedirectGateway: true,
				},
			},
			clientOptions: ClientOptions{
				Pull: ClientPullOptions{Enabled: true},
			},
			payload: []byte("loopback-push-basic"),
			verifyConfiguration: func(configurationTest *testing.T, configuration TunnelConfiguration) {
				configurationTest.Helper()
				if configuration.Topology != "subnet" {
					configurationTest.Fatalf("unexpected topology: %q", configuration.Topology)
				}
				if configuration.TunMTU != 1412 {
					configurationTest.Fatalf("unexpected tun_mtu: %d", configuration.TunMTU)
				}
				if len(configuration.LocalIPv4) != 1 || configuration.LocalIPv4[0] != netip.MustParsePrefix("10.8.0.2/24") {
					configurationTest.Fatalf("unexpected local ipv4: %+v", configuration.LocalIPv4)
				}
				if configuration.RouteGateway != netip.MustParseAddr("10.8.0.1") {
					configurationTest.Fatalf("unexpected route_gateway: %s", configuration.RouteGateway)
				}
				if len(configuration.IPv4Routes) != 1 || configuration.IPv4Routes[0].Prefix != netip.MustParsePrefix("10.9.0.0/24") {
					configurationTest.Fatalf("unexpected route: %+v", configuration.IPv4Routes)
				}
				if len(configuration.IPv6Routes) != 1 || configuration.IPv6Routes[0].Prefix != netip.MustParsePrefix("fd10::/64") {
					configurationTest.Fatalf("unexpected route_ipv6: %+v", configuration.IPv6Routes)
				}
				if len(configuration.DNS) != 1 || configuration.DNS[0] != netip.MustParseAddr("1.1.1.1") {
					configurationTest.Fatalf("unexpected DNS: %+v", configuration.DNS)
				}
				if !configuration.RedirectGateway {
					configurationTest.Fatal("expected redirect_gateway")
				}
			},
		},
		{
			name:     "tls_udp_route_nopull",
			protocol: "udp",
			serverOptions: ServerOptions{
				Push: ServerPushOptions{
					Routes:          []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")},
					DNS:             []netip.Addr{netip.MustParseAddr("1.1.1.1")},
					RedirectGateway: true,
				},
			},
			clientOptions: ClientOptions{
				Pull: ClientPullOptions{Enabled: true, RouteNoPull: true},
			},
			payload: []byte("loopback-route-nopull"),
			verifyConfiguration: func(configurationTest *testing.T, configuration TunnelConfiguration) {
				configurationTest.Helper()
				if len(configuration.LocalIPv4) != 1 || configuration.LocalIPv4[0] != netip.MustParsePrefix("10.8.0.2/24") {
					configurationTest.Fatalf("unexpected local ipv4: %+v", configuration.LocalIPv4)
				}
				if len(configuration.IPv4Routes) != 0 {
					configurationTest.Fatalf("route should be empty with route_nopull: %+v", configuration.IPv4Routes)
				}
				if configuration.RouteGateway != netip.MustParseAddr("10.8.0.1") {
					configurationTest.Fatalf("route_gateway should remain available with route_nopull: %s", configuration.RouteGateway)
				}
				if configuration.RedirectGateway {
					configurationTest.Fatal("redirect_gateway should be false with route_nopull")
				}
				if len(configuration.DNS) != 0 {
					configurationTest.Fatalf("DNS should be empty with route_nopull: %+v", configuration.DNS)
				}
			},
		},
		{
			name:     "tls_udp_explicit_mode",
			protocol: "udp",
			serverOptions: ServerOptions{
				Mode: ModeTLS,
				TLS: ServerTLSOptions{
					CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
					Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
					Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
				},
			},
			clientOptions: ClientOptions{
				Mode: ModeTLS,
				TLS: ClientTLSOptions{
					CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
					Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
					Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
				},
			},
			payload: []byte("loopback-tls-explicit-udp"),
		},
		{
			name:     "tls_tcp_explicit_mode",
			protocol: "tcp",
			serverOptions: ServerOptions{
				Mode: ModeTLS,
				TLS: ServerTLSOptions{
					CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
					Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
					Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
				},
			},
			clientOptions: ClientOptions{
				Mode: ModeTLS,
				TLS: ClientTLSOptions{
					CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
					Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
					Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
				},
			},
			payload: []byte("loopback-tls-explicit-tcp"),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(scenarioTest *testing.T) {
			scenarioTest.Parallel()
			runLoopbackScenario(scenarioTest, testCase)
		})
	}
}

func runLoopbackScenario(t *testing.T, scenario loopbackScenario) {
	t.Helper()
	listenAddress := reserveListenAddressForProtocol(t, scenario.protocol)
	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelServerContext()
	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelClientContext()

	serverOptions := scenario.serverOptions
	serverOptions.Context = serverContext
	serverOptions.Transport.ListenAddress = listenAddress
	serverOptions.Transport.Protocol = scenario.protocol
	if serverOptions.Mode == "" {
		serverOptions.Mode = ModeTLS
	}
	if serverOptions.Mode == ModeTLS {
		if len(serverOptions.Tunnel.AddressPools) == 0 {
			serverOptions.Tunnel.AddressPools = []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")}
		}
		if serverOptions.Tunnel.Topology == "" {
			serverOptions.Tunnel.Topology = "subnet"
		}
		if !serverOptions.TLS.CertificateAuthority.IsSet() {
			serverOptions.TLS.CertificateAuthority = Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")}
		}
		if !serverOptions.TLS.Certificate.IsSet() {
			serverOptions.TLS.Certificate = Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")}
		}
		if !serverOptions.TLS.Key.IsSet() {
			serverOptions.TLS.Key = Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")}
		}
	}
	server, err := NewServer(serverOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}

	clientOptions := scenario.clientOptions
	clientOptions.Context = clientContext
	clientOptions.Transport = clientTransportOptions(t, listenAddress, scenario.protocol)
	if clientOptions.Mode == "" {
		clientOptions.Mode = ModeTLS
	}
	if clientOptions.Mode == ModeTLS {
		clientOptions.Pull.Enabled = true
		if !clientOptions.TLS.CertificateAuthority.IsSet() {
			clientOptions.TLS.CertificateAuthority = Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")}
		}
		if !clientOptions.TLS.Certificate.IsSet() {
			clientOptions.TLS.Certificate = Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")}
		}
		if !clientOptions.TLS.Key.IsSet() {
			clientOptions.TLS.Key = Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")}
		}
	}
	client, err := NewClient(clientOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	waitForClientReady(t, client, 5*time.Second)

	var tunnelConfiguration TunnelConfiguration
	if clientOptions.Mode == ModeTLS && clientOptions.Pull.Enabled {
		tunnelConfiguration = waitForClientIfconfig(t, client, 5*time.Second)
	}
	if scenario.verifyConfiguration != nil {
		if len(tunnelConfiguration.LocalIPv4) == 0 {
			tunnelConfiguration = waitForClientIfconfig(t, client, 5*time.Second)
		}
		scenario.verifyConfiguration(t, tunnelConfiguration)
	}

	serverDone := make(chan error, 1)
	go func() {
		packetContext, cancelPacketContext := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelPacketContext()
		packet, readErr := server.ReadDataPacket(packetContext)
		if readErr != nil {
			serverDone <- readErr
			return
		}
		serverDone <- server.WriteDataPacket(packet.PeerAddress, packet.Payload)
	}()

	wirePayload := scenario.payload
	if clientOptions.Mode == ModeTLS {
		clientAddress := "10.8.0.2"
		if len(tunnelConfiguration.LocalIPv4) > 0 {
			clientAddress = tunnelConfiguration.LocalIPv4[0].Addr().String()
		}
		wirePayload = makeIPv4TestPacket(clientAddress, "10.8.0.1", scenario.payload)
	}
	err = client.WriteDataPacket(wirePayload)
	if err != nil {
		t.Fatal(err)
	}
	replyContext, cancelReplyContext := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelReplyContext()
	reply, err := client.ReadDataPacket(replyContext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, wirePayload) {
		t.Fatalf("unexpected reply payload: %q", reply)
	}
	if serverErr := <-serverDone; serverErr != nil {
		t.Fatal(serverErr)
	}
}
