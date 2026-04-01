package test

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/docker/go-connections/nat"
)

func TestOpenVPNInteropClientToRealServer(t *testing.T) {
	runInteropDirection(t, interopDirectionClientToRealServer)
}

func TestOpenVPNInteropRealClientToRepoServer(t *testing.T) {
	runInteropDirection(t, interopDirectionRealClientToServer)
}

func runInteropDirection(t *testing.T, direction interopDirection) {
	t.Helper()
	for _, scenario := range openVPNInteropScenarios {
		if scenario.Direction != direction {
			continue
		}
		t.Run(scenario.Name, func(scenarioTest *testing.T) {
			if scenario.Current == interopCurrentSkip {
				scenarioTest.Skip(scenario.SkipReason)
			}
			if scenario.Direction == interopDirectionClientToRealServer {
				runCount := 0
				for _, version := range []string{"2.4.12", "2.5.11", "2.6.14"} {
					if !interopScenarioSupportsVersion(scenario, version) {
						continue
					}
					runCount++
					scenarioTest.Run("openvpn_"+version, func(versionTest *testing.T) {
						env := requireInteropEnvironmentVersion(versionTest, version)
						runInteropScenario(versionTest, env, scenario)
					})
				}
				if runCount == 0 {
					scenarioTest.Fatal("scenario has no supported OpenVPN server version")
				}
				return
			}
			runInteropScenario(scenarioTest, requireInteropEnvironmentVersion(scenarioTest, openVPNInteropDefaultVersion), scenario)
		})
	}
}

func runInteropScenario(t *testing.T, env interopEnvironment, scenario interopScenario) {
	t.Helper()
	switch {
	case scenario.Direction == interopDirectionClientToRealServer && scenario.Mode == "static_key":
		runStaticClientToRealServerScenario(t, env, scenario)
	case scenario.Direction == interopDirectionClientToRealServer && scenario.Mode == "tls":
		runTLSClientToRealServerScenario(t, env, scenario)
	case scenario.Direction == interopDirectionRealClientToServer && scenario.Mode == "tls":
		runTLSRealClientToRepoServerScenario(t, env, scenario)
	default:
		t.Fatalf("missing runner for current-pass scenario %s", scenario.Name)
	}
}

func interopScenarioSupportsVersion(scenario interopScenario, version string) bool {
	versionRank := interopVersionRank(version)
	if versionRank < 26 && !scenario.LegacyServerMatrix {
		return false
	}
	if scenario.MinOpenVPN != "" && versionRank < interopVersionRank(scenario.MinOpenVPN) {
		return false
	}
	return scenario.MaxOpenVPN == "" || versionRank <= interopVersionRank(scenario.MaxOpenVPN)
}

func interopVersionRank(version string) int {
	switch {
	case strings.HasPrefix(version, "2.4"):
		return 24
	case strings.HasPrefix(version, "2.5"):
		return 25
	case strings.HasPrefix(version, "2.6"):
		return 26
	default:
		return -1
	}
}

func runStaticClientToRealServerScenario(t *testing.T, env interopEnvironment, scenario interopScenario) {
	t.Helper()
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	var (
		serverPort     int
		clientPort     int
		portBindings   nat.PortMap
		serverProtocol string
		serverReady    []string
	)
	serverKeyDirection := 0
	clientKeyDirection := 1
	if scenario.StaticKeyDirectionless {
		serverKeyDirection = -1
		clientKeyDirection = -1
	}
	if strings.HasPrefix(scenario.Protocol, "tcp") {
		serverPort = reserveTCPPort(t)
		clientPort = reserveTCPPort(t)
		portBindings = tcpPortBinding(serverPort)
		serverProtocol = staticInteropProtocolName(scenario.Protocol, true)
		serverReady = []string{"Listening for incoming TCP connection"}
	} else {
		serverPort = reserveUDPPort(t)
		clientPort = reserveUDPPort(t)
		portBindings = udpPortBinding(serverPort)
		serverProtocol = staticInteropProtocolName(scenario.Protocol, true)
		serverReady = []string{"UDPv4 link remote", "UDPv6 link remote"}
	}
	renderInteropTemplate(t, "static-peer.conf.tmpl", filepath.Join(workspace.renderedDir, "server-static.conf"), staticPeerTemplateData{
		Protocol:     serverProtocol,
		LocalHost:    "0.0.0.0",
		LocalPort:    serverPort,
		RemoteHost:   staticInteropRemoteHost(scenario.Protocol, "host.docker.internal"),
		RemotePort:   clientPort,
		UseFloat:     !strings.HasPrefix(scenario.Protocol, "tcp"),
		TunnelLocal:  "10.1.0.1",
		TunnelRemote: "10.1.0.2",
		SecretPath:   filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "static.key")),
		KeyDirection: serverKeyDirection,
		Cipher:       scenario.Cipher,
		Auth:         scenario.Auth,
		LogPath:      filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "server.log")),
	})
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-real-server-" + sanitizeDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "server-static.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: portBindings,
		Privileged:   true,
	})
	waitForAnyLogLine(t, filepath.Join(workspace.logsDir, "server.log"), serverReady, 20*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clientOptions := openvpn.ClientOptions{
		Context: ctx,
		Mode:    scenario.Mode,
		Transport: openvpn.ClientTransportOptions{
			Remotes:     []openvpn.Remote{clientRemote(t, net.JoinHostPort(staticInteropLoopbackHost(scenario.Protocol), fmt.Sprintf("%d", serverPort)), scenario.Protocol)},
			DialContext: bindPortDialContextWithRecorder(clientPort, nil),
			Protocol:    scenario.Protocol,
		},
		DataChannel: openvpn.ClientDataChannelOptions{
			Cipher: scenario.Cipher,
			Auth:   scenario.Auth,
		},
		StaticKey:    openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "static.key")},
		KeyDirection: clientKeyDirection,
	}
	client, err := openvpn.NewClient(clientOptions)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatalf("start client: %v", err)
	}
	sourceAddress := netip.MustParseAddr("10.1.0.2")
	destinationAddress := netip.MustParseAddr("10.1.0.1")
	request := buildStaticICMPEchoRequest(t,
		sourceAddress,
		destinationAddress,
		0x1234,
		1,
		[]byte("sing-openvpn-static"),
	)
	writeClientDataPacket(t, client, request, 10*time.Second)
	replyContext, cancelReply := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelReply()
	for {
		reply, readErr := client.ReadDataPacket(replyContext)
		if readErr != nil {
			t.Fatalf("read data packet: %v", readErr)
		}
		if validateStaticICMPEchoReply(request, reply) != nil {
			continue
		}
		assertStaticICMPEchoReply(t, request, reply)
		break
	}
}

func staticInteropProtocolName(protocol string, server bool) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "tcp", "tcp4":
		if server {
			return "tcp4-server"
		}
		return "tcp4-client"
	case "tcp6":
		if server {
			return "tcp6-server"
		}
		return "tcp6-client"
	default:
		return protocol
	}
}

func staticInteropLoopbackHost(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "udp6", "tcp6":
		return "::1"
	default:
		return "127.0.0.1"
	}
}

func staticInteropRemoteHost(protocol string, host string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(protocol)), "tcp") {
		return ""
	}
	return host
}

func runTLSClientToRealServerScenario(t *testing.T, env interopEnvironment, scenario interopScenario) {
	t.Helper()
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	var (
		serverPort   int
		clientPort   int
		portBindings nat.PortMap
	)
	if strings.HasPrefix(scenario.Protocol, "tcp") {
		if strings.HasSuffix(scenario.Protocol, "6") {
			serverPort = reserveTCPPort(t)
			clientPort = reserveTCPPort(t)
			portBindings = tcp6PortBinding(serverPort)
		} else {
			serverPort = reserveTCPPort(t)
			clientPort = reserveTCPPort(t)
			portBindings = tcpPortBinding(serverPort)
		}
	} else {
		serverPort = reserveUDPPort(t)
		clientPort = reserveUDPPort(t)
		if strings.HasSuffix(scenario.Protocol, "6") {
			portBindings = udp6PortBinding(serverPort)
		} else {
			portBindings = udpPortBinding(serverPort)
		}
	}

	serverDataCiphers := scenario.DataCiphers
	if len(scenario.PeerDataCiphers) > 0 {
		serverDataCiphers = scenario.PeerDataCiphers
	}
	dataCiphersDirective := "data-ciphers"
	if interopVersionRank(env.version) == 24 {
		dataCiphersDirective = "ncp-ciphers"
	}
	tlsCryptV2Option := "allow-noncookie"
	if scenario.TLSCryptV2ForceCookie {
		tlsCryptV2Option = "force-cookie"
	}
	renderInteropTemplate(t, "tls-server.conf.tmpl", filepath.Join(workspace.renderedDir, "server-tls.conf"), tlsServerTemplateData{
		Protocol:             scenario.Protocol,
		Port:                 serverPort,
		CAPath:               filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		CertPath:             filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		KeyPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		TLSAuthPath:          dockerPathIf(scenario.UseTLSAuth, "fixtures", "ta.key"),
		TLSCryptPath:         dockerPathIf(scenario.UseTLSCrypt, "fixtures", "tls-crypt.key"),
		TLSCryptV2Path:       dockerPathIf(scenario.UseTLSCryptV2, "fixtures", "tls-crypt-v2-server.key"),
		TLSCryptV2Option:     tlsCryptV2Option,
		Cipher:               scenario.Cipher,
		Auth:                 scenario.Auth,
		DataCiphersDirective: dataCiphersDirective,
		DataCiphers:          strings.Join(serverDataCiphers, ":"),
		TunMTU:               scenario.PushConfiguration.TunMTU,
		Fragment:             scenario.Fragment,
		Compression:          scenario.Compression,
		CompressionLZO:       scenario.CompressionLZO,
		RenegotiationSeconds: int64(scenario.RenegotiationInterval / time.Second),
		RequireUserPass:      scenario.UseAuthUserPass,
		AuthScriptPath:       filepath.ToSlash(filepath.Join(openVPNInteropRoot, "scripts", "check_userpass.sh")),
		PushLines:            pushLinesForScenario(scenario.PushConfiguration),
		LogPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "server.log")),
	})
	serverContainer := startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-real-server-" + sanitizeDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "server-tls.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: portBindings,
		Privileged:   true,
	})
	waitForLogLine(t, filepath.Join(workspace.logsDir, "server.log"), "Initialization Sequence Completed", 20*time.Second)

	clientContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	retryingTLSStartFailure := strings.EqualFold(scenario.ExpectStartErrorContain, "tls")
	var tunnelConfigurationEvents chan openvpn.TunnelConfigurationEvent
	packetLengthRecorder := new(interopPacketLengthRecorder)
	clientOptions := openvpn.ClientOptions{
		Context: clientContext,
		Mode:    scenario.Mode,
		Transport: openvpn.ClientTransportOptions{
			Remotes:     []openvpn.Remote{clientRemote(t, net.JoinHostPort(staticInteropLoopbackHost(scenario.Protocol), fmt.Sprintf("%d", serverPort)), scenario.Protocol)},
			DialContext: bindPortDialContextWithRecorder(clientPort, packetLengthRecorder),
			Protocol:    scenario.Protocol,
		},
		DataChannel: openvpn.ClientDataChannelOptions{
			Cipher:           scenario.Cipher,
			Ciphers:          slices.Clone(scenario.DataCiphers),
			Auth:             scenario.Auth,
			MSSFix:           scenario.MSSFix,
			Fragment:         scenario.Fragment,
			Compression:      scenario.Compression,
			CompressionLZO:   scenario.CompressionLZO,
			AllowCompression: scenario.AllowCompression,
		},
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: tlsFixturePath(scenario, false, "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Authentication: openvpn.ClientAuthenticationOptions{Username: "test-user", Password: "test-password"},
		Pull: openvpn.ClientPullOptions{
			Enabled:     true,
			RouteNoPull: scenario.RouteNoPull,
		},
		Timing: openvpn.ClientTimingOptions{
			RenegotiationPackets: scenario.RenegotiationPackets,
		},
		KeyDirection: 1,
	}
	if scenario.RenegotiationInterval != 0 {
		clientOptions.Timing.RenegotiationInterval = scenario.RenegotiationInterval
	}
	if scenario.ExpectStartErrorContain != "" {
		clientOptions.Timing.HandWindow = 5 * time.Second
		clientOptions.Timing.TLSTimeout = time.Second
	}
	if retryingTLSStartFailure {
		clientOptions.Timing.HandWindow = 2 * time.Second
		tunnelConfigurationEvents = make(chan openvpn.TunnelConfigurationEvent, 4)
		clientOptions.OnTunnelConfiguration = func(event openvpn.TunnelConfigurationEvent) error {
			select {
			case tunnelConfigurationEvents <- event:
			default:
			}
			return nil
		}
	}
	if scenario.UseTLSAuth {
		tlsAuthPath := filepath.Join("testdata", "openvpn", "pki", "ta.key")
		if strings.Contains(scenario.Name, "wrong_tls_auth") {
			tlsAuthPath = tamperedStaticKeyPath(t, tlsAuthPath)
		}
		clientOptions.TLS.Auth = openvpn.Material{Path: tlsAuthPath}
	}
	if scenario.UseTLSCrypt {
		tlsCryptPath := filepath.Join("testdata", "openvpn", "pki", "tls-crypt.key")
		if strings.Contains(scenario.Name, "wrong_tls_crypt") {
			tlsCryptPath = tamperedStaticKeyPath(t, tlsCryptPath)
		}
		clientOptions.TLS.Crypt = openvpn.Material{Path: tlsCryptPath}
	}
	if scenario.UseTLSCryptV2 {
		clientOptions.TLS.CryptV2 = openvpn.Material{Path: tlsFixturePath(scenario, false, "tls-crypt-v2-client.key")}
	}
	if scenario.UseAuthUserPass && strings.Contains(scenario.Name, "wrong_auth_user_pass") {
		clientOptions.Authentication.Username = "bad-user"
		clientOptions.Authentication.Password = "bad-password"
	}

	client, err := openvpn.NewClient(clientOptions)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()
	startErr := client.Start()
	if scenario.ExpectStartErrorContain != "" {
		if startErr != nil {
			if retryingTLSStartFailure {
				t.Fatalf("unexpected terminal start error for retryable TLS startup failure: %v", startErr)
			}
			assertExpectedClientStartError(t, startErr, scenario.ExpectStartErrorContain)
			return
		}
		if retryingTLSStartFailure {
			assertClientDoesNotEstablish(t, client, tunnelConfigurationEvents, 5*time.Second)
			return
		}
		waitForClientStartError(t, client, scenario.ExpectStartErrorContain, 10*time.Second)
		return
	}
	if startErr != nil {
		t.Fatalf("start client: %v", startErr)
	}

	configuration := waitForClientIfconfig(t, client, 10*time.Second)
	assertExpectedTunnelConfiguration(t, scenario, env.version, configuration)
	recordPacketLengths := scenario.Fragment > 0 || scenario.Compression != "" || scenario.CompressionLZO != ""
	if recordPacketLengths {
		packetLengthRecorder.Begin()
	}
	var mssCapture *interopPacketCapture
	if scenario.MSSFix > 0 {
		mssCapture = startInteropPacketCapture(t, serverContainer, workspace, "inner-mss", "dst host 10.8.0.1 and tcp[tcpflags] & tcp-syn != 0")
	}
	if scenario.ExpectEcho {
		initialEchoCount := 1
		if scenario.ExpectGenerationChange && scenario.RenegotiationPackets > 0 {
			initialEchoCount = int(scenario.RenegotiationPackets)
		}
		for i := 1; i <= initialEchoCount; i++ {
			exchangeTLSClientEcho(t, client, configuration, uint16(i), scenario.EchoPayloadSize)
		}
	}
	if recordPacketLengths {
		_, writePacketLengths := packetLengthRecorder.End()
		if scenario.Fragment > 0 {
			assertFragmentedUDPPackets(t, writePacketLengths, int(scenario.Fragment))
		}
		if scenario.Compression != "" || scenario.CompressionLZO != "" {
			assertCompressedUDPPackets(t, writePacketLengths, scenario.EchoPayloadSize)
		}
	}
	if mssCapture != nil {
		sourceAddress, destinationAddress := tunnelEchoAddresses(configuration)
		synPacket := buildIPv4TCPSYNPacket(t, sourceAddress, destinationAddress, 0x9c40, 9, 1460)
		writeClientDataPacket(t, client, synPacket, 10*time.Second)
		decodedPackets := mssCapture.Decode(t)
		expectedMSS := "mss " + fmt.Sprintf("%d", scenario.ExpectedMSS)
		if !strings.Contains(decodedPackets, expectedMSS) {
			t.Fatalf("expected %q in peer TUN capture:\n%s", expectedMSS, decodedPackets)
		}
	}
	if scenario.ExpectGenerationChange {
		waitForLogOccurrences(t, filepath.Join(workspace.logsDir, "server.log"), "Outgoing Data Channel: Cipher", 2, 15*time.Second)
		exchangeTLSClientEcho(t, client, configuration, uint16(scenario.RenegotiationPackets+1), scenario.EchoPayloadSize)
	}
	assertLogContains(t, filepath.Join(workspace.logsDir, "server.log"), scenario.ExpectServerLogContains)
}

func assertExpectedTunnelConfiguration(t *testing.T, scenario interopScenario, openVPNVersion string, actual openvpn.TunnelConfiguration) {
	t.Helper()
	expected := scenario.ExpectedConfiguration
	if expected.Topology != "" && actual.Topology != expected.Topology {
		t.Fatalf("expected pushed topology %q, got %q", expected.Topology, actual.Topology)
	}
	if expected.TunMTU > 0 && actual.TunMTU != expected.TunMTU {
		t.Fatalf("expected pushed tunnel MTU %d, got %d", expected.TunMTU, actual.TunMTU)
	}
	if expected.LocalIPv4 != nil && !slices.Equal(actual.LocalIPv4, expected.LocalIPv4) {
		t.Fatalf("expected pushed IPv4 addresses %v, got %v", expected.LocalIPv4, actual.LocalIPv4)
	}
	if expected.LocalIPv6 != nil && !slices.Equal(actual.LocalIPv6, expected.LocalIPv6) {
		t.Fatalf("expected pushed IPv6 addresses %v, got %v", expected.LocalIPv6, actual.LocalIPv6)
	}
	if expected.VPNGateway.IsValid() && actual.VPNGateway != expected.VPNGateway {
		t.Fatalf("expected pushed IPv4 VPN gateway %s, got %s", expected.VPNGateway, actual.VPNGateway)
	}
	if expected.VPNGatewayIPv6.IsValid() && actual.VPNGatewayIPv6 != expected.VPNGatewayIPv6 {
		t.Fatalf("expected pushed IPv6 VPN gateway %s, got %s", expected.VPNGatewayIPv6, actual.VPNGatewayIPv6)
	}
	if expected.RouteGateway.IsValid() && actual.RouteGateway != expected.RouteGateway {
		t.Fatalf("expected pushed route gateway %s, got %s", expected.RouteGateway, actual.RouteGateway)
	}
	if expected.IPv4Routes != nil && !slices.Equal(actual.IPv4Routes, expected.IPv4Routes) {
		t.Fatalf("expected pushed IPv4 routes %v, got %v", expected.IPv4Routes, actual.IPv4Routes)
	}
	if expected.IPv6Routes != nil && !slices.Equal(actual.IPv6Routes, expected.IPv6Routes) {
		t.Fatalf("expected pushed IPv6 routes %v, got %v", expected.IPv6Routes, actual.IPv6Routes)
	}
	if expected.DNS != nil && !slices.Equal(actual.DNS, expected.DNS) {
		t.Fatalf("expected pushed DNS addresses %v, got %v", expected.DNS, actual.DNS)
	}
	if expected.DHCPOptions != nil && !slices.Equal(actual.DHCPOptions, expected.DHCPOptions) {
		t.Fatalf("expected pushed DHCP options %v, got %v", expected.DHCPOptions, actual.DHCPOptions)
	}
	if expected.RedirectGateway && !actual.RedirectGateway {
		t.Fatal("expected pushed redirect-gateway to be retained")
	}
	if expected.SelectedCipher != "" && interopVersionRank(openVPNVersion) >= 25 && actual.SelectedCipher != expected.SelectedCipher {
		t.Fatalf("expected negotiated data cipher %q, got %q", expected.SelectedCipher, actual.SelectedCipher)
	}
	if scenario.RouteNoPull {
		if actual.RouteGateway.IsValid() {
			t.Fatalf("route-nopull retained pushed route gateway %s", actual.RouteGateway)
		}
		if len(actual.IPv4Routes) != 0 || len(actual.IPv6Routes) != 0 {
			t.Fatalf("route-nopull retained pushed routes: IPv4=%v IPv6=%v", actual.IPv4Routes, actual.IPv6Routes)
		}
		if actual.RedirectGateway || actual.RedirectPrivate {
			t.Fatalf("route-nopull retained pushed redirect: gateway=%t private=%t", actual.RedirectGateway, actual.RedirectPrivate)
		}
	}
}

func exchangeTLSClientEcho(t *testing.T, client *openvpn.Client, configuration openvpn.TunnelConfiguration, sequence uint16, payloadSize int) {
	t.Helper()
	sourceAddress, destinationAddress := tunnelEchoAddresses(configuration)
	payload := buildInteropEchoPayload(payloadSize)
	request := buildStaticICMPEchoRequest(t, sourceAddress, destinationAddress, 0x1234, sequence, payload)
	writeClientDataPacket(t, client, request, 10*time.Second)
	replyContext, cancelReply := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelReply()
	for {
		reply, err := client.ReadDataPacket(replyContext)
		if err != nil {
			t.Fatalf("read data packet: %v", err)
		}
		if validateStaticICMPEchoReply(request, reply) == nil {
			return
		}
	}
}

func tunnelEchoAddresses(configuration openvpn.TunnelConfiguration) (netip.Addr, netip.Addr) {
	sourceAddress := configuration.LocalIPv4[0].Addr()
	destinationAddress := netip.MustParseAddr("10.8.0.1")
	if configuration.RouteGateway.Is4() {
		destinationAddress = configuration.RouteGateway
	}
	return sourceAddress, destinationAddress
}

func assertFragmentedUDPPackets(t *testing.T, packetLengths []int, fragmentSize int) {
	t.Helper()
	fragmentCount := 0
	for _, packetLength := range packetLengths {
		if packetLength > fragmentSize {
			t.Fatalf("outer UDP packet length %d exceeds fragment size %d: %v", packetLength, fragmentSize, packetLengths)
		}
		if packetLength > 64 {
			fragmentCount++
		}
	}
	if fragmentCount < 2 {
		t.Fatalf("expected multiple OpenVPN fragments, got UDP packet lengths %v", packetLengths)
	}
}

func assertCompressedUDPPackets(t *testing.T, packetLengths []int, originalPayloadSize int) {
	t.Helper()
	maxPacketLength := 0
	for _, packetLength := range packetLengths {
		if packetLength > maxPacketLength {
			maxPacketLength = packetLength
		}
	}
	if maxPacketLength >= originalPayloadSize/2 {
		t.Fatalf("expected compressed outer UDP packet below %d bytes, got %v", originalPayloadSize/2, packetLengths)
	}
}

func runTLSRealClientToRepoServerScenario(t *testing.T, env interopEnvironment, scenario interopScenario) {
	t.Helper()
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	var listenPort int
	if strings.HasPrefix(scenario.Protocol, "tcp") {
		listenPort = reserveTCPPort(t)
	} else {
		listenPort = reserveUDPPort(t)
	}

	pushConfiguration := baseTLSPushConfiguration()
	pushConfiguration = mergeTunnelConfiguration(pushConfiguration, scenario.PushConfiguration)
	if (pushConfiguration.Topology == "p2p" || pushConfiguration.Topology == "net30") && !scenario.PushConfiguration.RouteGateway.IsValid() {
		pushConfiguration.RouteGateway = netip.Addr{}
	}
	serverContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	serverOptions := openvpn.ServerOptions{
		Context: serverContext,
		Mode:    scenario.Mode,
		Transport: openvpn.ServerTransportOptions{
			ListenAddress: fmt.Sprintf("0.0.0.0:%d", listenPort),
			Protocol:      scenario.Protocol,
		},
		DataChannel: openvpn.ServerDataChannelOptions{
			MTU:            pushConfiguration.TunMTU,
			Ciphers:        slices.Clone(scenario.DataCiphers),
			FallbackCipher: scenario.Cipher,
			Auth:           scenario.Auth,
		},
		TLS: openvpn.ServerTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Tunnel: openvpn.ServerTunnelOptions{
			AddressPools: append(slices.Clone(pushConfiguration.LocalIPv4), pushConfiguration.LocalIPv6...),
			Topology:     pushConfiguration.Topology,
			LocalAddress: serverLocalAddressForPushedIPv6(pushConfiguration.LocalIPv6),
		},
		Push: openvpn.ServerPushOptions{
			Routes:          tunnelRoutePrefixes(pushConfiguration.IPv4Routes, pushConfiguration.IPv6Routes),
			DNS:             slices.Clone(pushConfiguration.DNS),
			RedirectGateway: pushConfiguration.RedirectGateway,
		},
		KeyDirection: 0,
	}
	if scenario.UseAuthUserPass {
		serverOptions.Authentication.Authenticator = func(_ context.Context, username string, password string) error {
			if username != "test-user" || password != "test-password" {
				return openvpn.ErrAuthenticationFailed
			}
			return nil
		}
	}
	if scenario.RenegotiationInterval != 0 {
		serverOptions.Timing.RenegotiationInterval = scenario.RenegotiationInterval
	}
	if scenario.UseTLSAuth {
		serverOptions.TLS.Auth = openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ta.key")}
	}
	if scenario.UseTLSCrypt {
		serverOptions.TLS.Crypt = openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "tls-crypt.key")}
	}
	if scenario.UseTLSCryptV2 {
		serverOptions.TLS.CryptV2 = openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "tls-crypt-v2-server.key")}
	}
	server, err := openvpn.NewServer(serverOptions)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatalf("start server: %v", err)
	}

	clientAuthPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "scripts", "auth-user-pass.txt"))
	if scenario.UseAuthUserPass && strings.Contains(scenario.Name, "wrong_auth_user_pass") {
		badAuthPath := filepath.Join(workspace.root, "scripts", "bad-auth-user-pass.txt")
		err = os.WriteFile(badAuthPath, []byte("bad-user\nbad-password\n"), 0o600)
		if err != nil {
			t.Fatalf("write bad auth file: %v", err)
		}
		clientAuthPath = filepath.ToSlash(filepath.Join(openVPNInteropRoot, "scripts", "bad-auth-user-pass.txt"))
	}
	clientTLSAuthPath := dockerPathIf(scenario.UseTLSAuth, "fixtures", "ta.key")
	clientTLSCryptPath := dockerPathIf(scenario.UseTLSCrypt, "fixtures", "tls-crypt.key")
	if scenario.UseTLSAuth && strings.Contains(scenario.Name, "wrong_tls_auth") {
		clientTLSAuthPath = filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ta.bad.key"))
		writeTamperedFixtureKey(t, filepath.Join(workspace.fixturesDir, "ta.bad.key"), filepath.Join("testdata", "openvpn", "pki", "ta.key"))
	}
	if scenario.UseTLSCrypt && strings.Contains(scenario.Name, "wrong_tls_crypt") {
		clientTLSCryptPath = filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "tls-crypt.bad.key"))
		writeTamperedFixtureKey(t, filepath.Join(workspace.fixturesDir, "tls-crypt.bad.key"), filepath.Join("testdata", "openvpn", "pki", "tls-crypt.key"))
	}
	clientDataCiphers := scenario.DataCiphers
	if len(scenario.PeerDataCiphers) > 0 {
		clientDataCiphers = scenario.PeerDataCiphers
	}
	renderInteropTemplate(t, "tls-client.conf.tmpl", filepath.Join(workspace.renderedDir, "client-tls.conf"), tlsClientTemplateData{
		Protocol:             scenario.Protocol,
		RemoteHost:           "host.docker.internal",
		RemotePort:           listenPort,
		CAPath:               filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		CertPath:             filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.crt")),
		KeyPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.key")),
		TLSAuthPath:          clientTLSAuthPath,
		TLSCryptPath:         clientTLSCryptPath,
		TLSCryptV2Path:       dockerPathIf(scenario.UseTLSCryptV2, "fixtures", "tls-crypt-v2-client.key"),
		Cipher:               scenario.Cipher,
		Auth:                 scenario.Auth,
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          strings.Join(clientDataCiphers, ":"),
		AuthFilePath:         clientAuthPath,
		LogPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "client.log")),
	})
	if scenario.ExpectStartErrorContain != "" {
		clientLogPath := filepath.Join(workspace.logsDir, "client.log")
		expectedFailureMarkers := []string{scenario.ExpectStartErrorContain}
		switch strings.ToLower(scenario.ExpectStartErrorContain) {
		case "auth":
			expectedFailureMarkers = []string{"auth_failed", "auth-failure"}
		case "tls":
			expectedFailureMarkers = []string{"tls error", "tls-error", "server poll timeout", "key negotiation failed"}
		}
		startInteropContainer(t, env.docker, dockerContainerOptions{
			Name:       "sing-openvpn-real-client-" + sanitizeDockerName(t.Name()),
			Image:      env.image,
			Command:    []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "client-tls.conf")) + " --connect-timeout 5 --connect-retry-max 1 --hand-window 5"},
			Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
			Privileged: true,
		})
		waitForAnyLogLine(t, clientLogPath, expectedFailureMarkers, 20*time.Second)
		return
	}
	initialPingCount := 1
	if scenario.ExpectGenerationChange && scenario.RenegotiationPackets > 0 {
		initialPingCount = int(scenario.RenegotiationPackets)
	}
	clientDataCommands := append(slices.Clone(scenario.RealClientChecks), "ping -c "+fmt.Sprintf("%d", initialPingCount)+" -W 3 10.8.0.1")
	clientDataCommand := strings.Join(clientDataCommands, " && ")
	if scenario.ExpectGenerationChange {
		clientLogPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "client.log"))
		clientDataCommand += " && until [ \"$(grep -c 'Outgoing Data Channel: Cipher' " + clientLogPath + ")\" -ge 2 ]; do sleep 0.1; done && ping -c 1 -W 3 10.8.0.1"
	}
	clientContainer := startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:       "sing-openvpn-real-client-" + sanitizeDockerName(t.Name()),
		Image:      env.image,
		Command:    []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "client-tls.conf")) + " --daemon --writepid " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "client.pid")) + " && until grep -q 'Initialization Sequence Completed' " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "client.log")) + "; do sleep 0.1; done && " + clientDataCommand},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})

	expectedEchoCount := 1
	if scenario.ExpectGenerationChange {
		expectedEchoCount = initialPingCount + 1
	}
	packetContext, cancelPacket := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelPacket()
	completedEchoCount := 0
	for completedEchoCount < expectedEchoCount {
		packet, readErr := server.ReadDataPacket(packetContext)
		if readErr != nil {
			t.Fatalf("read packet from real client: %v", readErr)
		}
		reply, replyErr := buildStaticICMPEchoReply(packet.Payload)
		if replyErr != nil {
			continue
		}
		writeErr := server.WriteDataPacket(packet.PeerAddress, reply)
		if writeErr != nil {
			t.Fatalf("write packet to real client: %v", writeErr)
		}
		completedEchoCount++
	}
	waitResult := clientContainer.Wait(t, 15*time.Second)
	if waitResult.ExitCode != 0 {
		t.Fatalf("real client container failed: %s", waitResult.Logs)
	}
	assertLogContains(t, filepath.Join(workspace.logsDir, "client.log"), scenario.ExpectClientLogContains)
}

func tlsFixturePath(scenario interopScenario, server bool, name string) string {
	switch {
	case strings.Contains(scenario.Name, "wrong_ca") && !server && name == "ca.crt":
		return filepath.Join("testdata", "openvpn", "pki", "client.crt")
	default:
		return filepath.Join("testdata", "openvpn", "pki", name)
	}
}

func dockerPathIf(enabled bool, elements ...string) string {
	if !enabled {
		return ""
	}
	return filepath.ToSlash(filepath.Join(append([]string{openVPNInteropRoot}, elements...)...))
}

func writeClientDataPacket(t *testing.T, client *openvpn.Client, packet []byte, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		err := client.WriteDataPacket(packet)
		if err == nil {
			return
		}
		if !E.IsMulti(err, openvpn.ErrDataChannelNotReady) {
			t.Fatalf("write data packet: %v", err)
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("timed out waiting for client data channel: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func assertClientDoesNotEstablish(t *testing.T, client *openvpn.Client, tunnelConfigurationEvents <-chan openvpn.TunnelConfigurationEvent, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	probePacket := []byte("probe-before-tunnel-ready")
	for time.Now().Before(deadline) {
		select {
		case event := <-tunnelConfigurationEvents:
			t.Fatalf("client unexpectedly established tunnel configuration: %+v", event.Configuration)
		default:
		}
		err := client.WriteDataPacket(probePacket)
		if err == nil {
			t.Fatal("client unexpectedly accepted data packet before tunnel establishment")
		}
		if !E.IsMulti(err, openvpn.ErrDataChannelNotReady) {
			t.Fatalf("unexpected write error before tunnel establishment: %v", err)
		}
		readContext, cancelRead := context.WithTimeout(context.Background(), 25*time.Millisecond)
		_, err = client.ReadDataPacket(readContext)
		cancelRead()
		if err == nil {
			t.Fatal("client unexpectedly read data packet before tunnel establishment")
		}
		if !E.IsMulti(err, context.DeadlineExceeded) {
			t.Fatalf("client entered terminal state instead of retrying startup: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case event := <-tunnelConfigurationEvents:
		t.Fatalf("client unexpectedly established tunnel configuration: %+v", event.Configuration)
	default:
	}
	err := client.Close()
	if err != nil && !E.IsMulti(err, net.ErrClosed) {
		t.Fatalf("close retrying client: %v", err)
	}
}

func waitForClientStartError(t *testing.T, client *openvpn.Client, expectedErrorText string, timeout time.Duration) {
	t.Helper()
	readContext, cancelRead := context.WithTimeout(context.Background(), timeout)
	defer cancelRead()
	_, err := client.ReadDataPacket(readContext)
	if err == nil {
		t.Fatalf("expected client start error containing %q", expectedErrorText)
	}
	assertExpectedClientStartError(t, err, expectedErrorText)
}

func assertExpectedClientStartError(t *testing.T, err error, expectedErrorText string) {
	t.Helper()
	normalizedExpected := strings.ToLower(expectedErrorText)
	normalizedError := strings.ToLower(err.Error())
	switch normalizedExpected {
	case "auth":
		if E.IsMulti(err, openvpn.ErrAuthenticationFailed) || strings.Contains(normalizedError, normalizedExpected) {
			return
		}
	case "certificate":
		if E.IsMulti(err, openvpn.ErrPeerCertificateVerification) || strings.Contains(normalizedError, normalizedExpected) {
			return
		}
	default:
		if strings.Contains(normalizedError, normalizedExpected) {
			return
		}
	}
	t.Fatalf("unexpected client start error: %v", err)
}

func tamperedStaticKeyPath(t *testing.T, sourcePath string) string {
	t.Helper()
	keyMaterial, err := loadStaticKeyMaterial(sourcePath)
	if err != nil {
		t.Fatalf("load static key %s: %v", sourcePath, err)
	}
	tamperedKeyMaterial := append([]byte{}, keyMaterial...)
	tamperedKeyMaterial[128] ^= 0xff
	tamperedKeyMaterial[192] ^= 0xff
	tamperedPath := filepath.Join(t.TempDir(), filepath.Base(sourcePath)+".tampered")
	err = os.WriteFile(tamperedPath, tamperedKeyMaterial, 0o600)
	if err != nil {
		t.Fatalf("write tampered static key: %v", err)
	}
	return tamperedPath
}

func writeTamperedFixtureKey(t *testing.T, targetPath string, sourcePath string) {
	t.Helper()
	keyMaterial, err := loadStaticKeyMaterial(sourcePath)
	if err != nil {
		t.Fatalf("load static key %s: %v", sourcePath, err)
	}
	tamperedKeyMaterial := append([]byte{}, keyMaterial...)
	tamperedKeyMaterial[128] ^= 0xff
	tamperedKeyMaterial[192] ^= 0xff
	err = os.WriteFile(targetPath, encodeOpenVPNStaticKey(tamperedKeyMaterial), 0o600)
	if err != nil {
		t.Fatalf("write tampered fixture key: %v", err)
	}
}

func encodeOpenVPNStaticKey(keyMaterial []byte) []byte {
	var builder strings.Builder
	builder.Grow(len(keyMaterial)*2 + len(keyMaterial)/16 + 96)
	builder.WriteString("#\n# 2048 bit OpenVPN static key\n#\n")
	builder.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for offset := 0; offset < len(keyMaterial); offset += 16 {
		lineEnd := min(offset+16, len(keyMaterial))
		builder.WriteString(hex.EncodeToString(keyMaterial[offset:lineEnd]))
		builder.WriteByte('\n')
	}
	builder.WriteString("-----END OpenVPN Static key V1-----\n")
	return []byte(builder.String())
}

func loadStaticKeyMaterial(sourcePath string) ([]byte, error) {
	content, err := os.ReadFile(sourcePath)
	if err != nil {
		return nil, err
	}
	hexContent := extractStaticKeyHex(string(content))
	if hexContent == "" {
		return nil, E.New("invalid static key content")
	}
	keyMaterial, err := hex.DecodeString(hexContent)
	if err != nil {
		return nil, err
	}
	if len(keyMaterial) < 256 {
		return nil, E.New("static key content too short")
	}
	return append([]byte{}, keyMaterial[:256]...), nil
}

func extractStaticKeyHex(content string) string {
	var builder strings.Builder
	for _, line := range strings.Split(content, "\n") {
		trimmedLine := strings.TrimSpace(line)
		switch {
		case trimmedLine == "":
			continue
		case strings.HasPrefix(trimmedLine, "#"):
			continue
		case strings.HasPrefix(trimmedLine, "-----"):
			continue
		default:
			builder.WriteString(trimmedLine)
		}
	}
	return builder.String()
}

func baseTLSPushConfiguration() openvpn.TunnelConfiguration {
	return openvpn.TunnelConfiguration{
		Topology:     "subnet",
		TunMTU:       1500,
		LocalIPv4:    []netip.Prefix{netip.MustParsePrefix("10.8.0.2/24")},
		RouteGateway: netip.MustParseAddr("10.8.0.1"),
	}
}

func mergeTunnelConfiguration(base openvpn.TunnelConfiguration, overlay openvpn.TunnelConfiguration) openvpn.TunnelConfiguration {
	merged := cloneTunnelConfiguration(base)
	if overlay.Topology != "" {
		merged.Topology = overlay.Topology
	}
	if overlay.TunMTU > 0 {
		merged.TunMTU = overlay.TunMTU
	}
	if len(overlay.LocalIPv4) > 0 {
		merged.LocalIPv4 = slices.Clone(overlay.LocalIPv4)
	}
	if len(overlay.LocalIPv6) > 0 {
		merged.LocalIPv6 = slices.Clone(overlay.LocalIPv6)
	}
	if overlay.RouteGateway.IsValid() {
		merged.RouteGateway = overlay.RouteGateway
	}
	if len(overlay.IPv4Routes) > 0 {
		merged.IPv4Routes = slices.Clone(overlay.IPv4Routes)
	}
	if len(overlay.IPv6Routes) > 0 {
		merged.IPv6Routes = slices.Clone(overlay.IPv6Routes)
	}
	if len(overlay.DNS) > 0 {
		merged.DNS = slices.Clone(overlay.DNS)
	}
	if len(overlay.DHCPOptions) > 0 {
		merged.DHCPOptions = slices.Clone(overlay.DHCPOptions)
	}
	if overlay.RedirectGateway {
		merged.RedirectGateway = true
	}
	return merged
}

func cloneTunnelConfiguration(configuration openvpn.TunnelConfiguration) openvpn.TunnelConfiguration {
	clonedConfiguration := configuration
	clonedConfiguration.LocalIPv4 = slices.Clone(configuration.LocalIPv4)
	clonedConfiguration.LocalIPv6 = slices.Clone(configuration.LocalIPv6)
	clonedConfiguration.IPv4Routes = slices.Clone(configuration.IPv4Routes)
	clonedConfiguration.IPv6Routes = slices.Clone(configuration.IPv6Routes)
	clonedConfiguration.DNS = slices.Clone(configuration.DNS)
	clonedConfiguration.DHCPOptions = slices.Clone(configuration.DHCPOptions)
	clonedConfiguration.RedirectGatewayFlags = slices.Clone(configuration.RedirectGatewayFlags)
	clonedConfiguration.ProtocolFlags = slices.Clone(configuration.ProtocolFlags)
	if configuration.PeerID != nil {
		peerID := *configuration.PeerID
		clonedConfiguration.PeerID = &peerID
	}
	return clonedConfiguration
}

func tunnelRoutePrefixes(routeGroups ...[]openvpn.TunnelRoute) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, routes := range routeGroups {
		for _, route := range routes {
			if route.Prefix.IsValid() {
				prefixes = append(prefixes, route.Prefix)
			}
		}
	}
	return prefixes
}

func serverLocalAddressForPushedIPv6(prefixes []netip.Prefix) []netip.Prefix {
	for _, prefix := range prefixes {
		if !prefix.IsValid() || !prefix.Addr().Is6() {
			continue
		}
		maskedPrefix := prefix.Masked()
		return []netip.Prefix{netip.PrefixFrom(maskedPrefix.Addr().Next(), maskedPrefix.Bits())}
	}
	return nil
}
