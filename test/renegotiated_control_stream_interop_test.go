package test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	renegotiatedControlStreamInterval = 2 * time.Second
	renegotiatedControlStreamBudget   = 20 * time.Second
)

// Upstream send_control_channel_string writes to session->key[KS_PRIMARY] and
// tls_rec_payload reads from it, so every control channel message follows the
// key state a soft reset promotes; tls_pre_decrypt drops a control packet whose
// key id belongs to the retired key state.
func TestOpenVPNInteropControlChannelFollowsRenegotiatedKeyState(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	t.Run("client_exit_notify_leaves_on_the_promoted_key_state", func(caseTest *testing.T) {
		caseTest.Parallel()
		runRenegotiatedClientExitNotifyCase(caseTest, env)
	})
	t.Run("server_reads_peer_exit_from_the_promoted_key_state", func(caseTest *testing.T) {
		caseTest.Parallel()
		runRenegotiatedServerPeerExitCase(caseTest, env)
	})
}

func runRenegotiatedClientExitNotifyCase(t *testing.T, env interopEnvironment) {
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	serverPort := reserveInteropPort(t, "udp")
	serverLogPath := filepath.Join(workspace.logsDir, "reneg-exit-server.log")
	renderInteropTemplate(t, "tls-server.conf.tmpl", filepath.Join(workspace.renderedDir, "reneg-exit-server.conf"), tlsServerTemplateData{
		Protocol:             "udp4",
		Port:                 serverPort,
		CAPath:               filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		CertPath:             filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		KeyPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		Cipher:               "AES-256-GCM",
		Auth:                 "SHA256",
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          "AES-256-GCM",
		LogPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "reneg-exit-server.log")),
	})
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-reneg-exit-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "reneg-exit-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	waitForLogLine(t, serverLogPath, "Initialization Sequence Completed", 20*time.Second)

	clientContext, cancelClient := context.WithTimeout(context.Background(), 90*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context: clientContext,
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ClientTransportOptions{
			Remotes:            []openvpn.Remote{{Host: "127.0.0.1", Port: uint16(serverPort), Protocol: "udp4"}},
			Protocol:           "udp4",
			ExplicitExitNotify: 1,
		},
		DataChannel: openvpn.ClientDataChannelOptions{
			Cipher:  "AES-256-GCM",
			Ciphers: []string{"AES-256-GCM"},
			Auth:    "SHA256",
		},
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
			RemoteCertificateTLS: "server",
		},
		Pull: openvpn.ClientPullOptions{Enabled: true},
		Timing: openvpn.ClientTimingOptions{
			HandWindow:            renegotiatedControlStreamBudget,
			RenegotiationInterval: renegotiatedControlStreamInterval,
		},
	})
	if err != nil {
		cancelClient()
		t.Fatalf("create renegotiated exit notify client: %v", err)
	}
	clientClosed := false
	t.Cleanup(func() {
		cancelClient()
		if clientClosed {
			return
		}
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close renegotiated exit notify client: %v", closeErr)
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatalf("start renegotiated exit notify client: %v", err)
	}
	configuration := waitForClientIfconfig(t, client, renegotiatedControlStreamBudget)
	if !slices.Contains(configuration.ProtocolFlags, "cc-exit") {
		t.Fatalf("the peer did not negotiate cc-exit, so the exit notification would never use the control channel: %v", configuration.ProtocolFlags)
	}
	exchangeControlLivenessEcho(t, client, configuration, 1)

	waitForLogOccurrences(t, serverLogPath, "Outgoing Data Channel: Cipher", 2, renegotiatedControlStreamBudget)
	exchangeControlLivenessEcho(t, client, configuration, 2)

	clientClosed = true
	closeErr := client.Close()
	if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
		t.Fatalf("close renegotiated exit notify client: %v", closeErr)
	}
	waitForAnyLogLine(t, serverLogPath, []string{"remote-exit", "Exit message received by peer"}, 15*time.Second)
}

func runRenegotiatedServerPeerExitCase(t *testing.T, env interopEnvironment) {
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	listenPort := reserveInteropPort(t, "udp")
	serverContext, cancelServer := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancelServer()
	server, err := openvpn.NewServer(openvpn.ServerOptions{
		NewOutboundQueue: newTestOutboundQueue,
		Context:          serverContext,
		Mode:             openvpn.ModeTLS,
		Transport: openvpn.ServerTransportOptions{
			ListenAddress: fmt.Sprintf("0.0.0.0:%d", listenPort),
			Protocol:      "udp4",
		},
		DataChannel: openvpn.ServerDataChannelOptions{
			Ciphers:        []string{"AES-256-GCM"},
			FallbackCipher: "AES-256-GCM",
			Auth:           "SHA256",
		},
		TLS: openvpn.ServerTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Tunnel: openvpn.ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
			Topology:     "subnet",
		},
		Timing: openvpn.ServerTimingOptions{RenegotiationInterval: renegotiatedControlStreamInterval},
	})
	if err != nil {
		t.Fatalf("create renegotiated peer exit server: %v", err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatalf("start renegotiated peer exit server: %v", err)
	}

	echoContext, cancelEcho := context.WithCancel(context.Background())
	defer cancelEcho()
	peerAddresses := new(observedPeerAddress)
	go serveRenegotiatedPeerEchoes(echoContext, server, peerAddresses)

	clientLogPath := filepath.Join(workspace.logsDir, "reneg-exit-client.log")
	dockerClientLogPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "reneg-exit-client.log"))
	dockerPIDPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "reneg-exit-client.pid"))
	renderInteropTemplate(t, "tls-client.conf.tmpl", filepath.Join(workspace.renderedDir, "reneg-exit-client.conf"), tlsClientTemplateData{
		Protocol:             "udp4",
		RemoteHost:           "host.docker.internal",
		RemotePort:           listenPort,
		CAPath:               filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		CertPath:             filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.crt")),
		KeyPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.key")),
		Cipher:               "AES-256-GCM",
		Auth:                 "SHA256",
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          "AES-256-GCM",
		ExplicitNotify:       true,
		LogPath:              dockerClientLogPath,
	})
	clientCommands := []string{
		"openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "reneg-exit-client.conf")) + " --daemon --writepid " + dockerPIDPath,
		"until grep -q 'Initialization Sequence Completed' " + dockerClientLogPath + "; do sleep 0.1; done",
		"ping -c 1 -W 3 10.8.0.1",
		"until [ \"$(grep -c 'Outgoing Data Channel: Cipher' " + dockerClientLogPath + ")\" -ge 2 ]; do sleep 0.1; done",
		"ping -c 1 -W 3 10.8.0.1",
		"kill -TERM $(cat " + dockerPIDPath + ")",
		"until grep -q 'process exiting' " + dockerClientLogPath + "; do sleep 0.1; done",
	}
	clientContainer := startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:       "sing-openvpn-reneg-exit-client-" + uniqueDockerName(t.Name()),
		Image:      env.image,
		Command:    []string{"bash", "-lc", strings.Join(clientCommands, " && ")},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})
	waitResult := clientContainer.Wait(t, 60*time.Second)
	if waitResult.ExitCode != 0 {
		t.Fatalf("renegotiated peer exit client container failed: %s", waitResult.Logs)
	}
	assertLogContains(t, clientLogPath, []string{"protocol-flags cc-exit"})

	peerAddress := peerAddresses.load()
	if peerAddress == "" {
		t.Fatal("the real OpenVPN client never delivered a data packet")
	}
	probe := buildStaticICMPEchoRequest(t,
		netip.MustParseAddr("10.8.0.1"),
		netip.MustParseAddr("10.8.0.2"),
		0x4821,
		1,
		[]byte("reneg-exit-probe"),
	)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		writeErr := server.WriteDataPacket(peerAddress, probe)
		if errors.Is(writeErr, openvpn.ErrPeerNotFound) {
			return
		}
		time.Sleep(interopPollInterval)
	}
	t.Fatal("the server kept serving the peer after its explicit exit notification arrived on the renegotiated key state")
}

type observedPeerAddress struct {
	access  sync.Mutex
	address string
}

func (o *observedPeerAddress) store(address string) {
	o.access.Lock()
	o.address = address
	o.access.Unlock()
}

func (o *observedPeerAddress) load() string {
	o.access.Lock()
	defer o.access.Unlock()
	return o.address
}

func serveRenegotiatedPeerEchoes(ctx context.Context, server *openvpn.Server, peerAddresses *observedPeerAddress) {
	for {
		packet, readErr := server.ReadDataPacket(ctx)
		if readErr != nil {
			return
		}
		peerAddresses.store(packet.PeerAddress)
		reply, replyErr := buildStaticICMPEchoReply(packet.Payload)
		if replyErr != nil {
			continue
		}
		_ = server.WriteDataPacket(packet.PeerAddress, reply)
	}
}
