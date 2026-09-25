package test

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	stalledRenegotiationInterval   = 4 * time.Second
	stalledRenegotiationHandWindow = 4 * time.Second
)

// key_state_init (ssl.c) stamps must_negotiate on the key_state a soft reset
// creates and tls_process fails that key_state alone once now passes it.  The
// link belongs to the whole instance: io_wait keeps serving the active
// key_state, the data channel and every other instance bound to the socket
// while a renegotiating key_state sits in a deferred authentication that
// outlives its hand window.
func TestOpenVPNInteropExpiredRenegotiationHandWindowKeepsDataChannelWriting(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	releaseAuthentication := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() {
			close(releaseAuthentication)
		})
	})
	var authenticationCalls atomic.Int64
	authenticator := func(ctx context.Context, username string, password string) error {
		if authenticationCalls.Add(1) == 1 {
			return nil
		}
		select {
		case <-releaseAuthentication:
		case <-ctx.Done():
		}
		return E.New("deferred authentication abandoned")
	}

	listenPort := reserveInteropPort(t, "udp")
	serverContext, cancelServer := context.WithTimeout(context.Background(), 180*time.Second)
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
		Authentication: openvpn.ServerAuthenticationOptions{Authenticator: authenticator},
		Tunnel: openvpn.ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
			Topology:     "subnet",
		},
		Timing: openvpn.ServerTimingOptions{
			RenegotiationInterval: stalledRenegotiationInterval,
			HandWindow:            stalledRenegotiationHandWindow,
		},
	})
	if err != nil {
		t.Fatalf("create stalled renegotiation server: %v", err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatalf("start stalled renegotiation server: %v", err)
	}

	peer := new(observedTunnelPeer)
	incomingReplies := make(chan []byte, 16)
	peerContext, cancelPeerLoop := context.WithCancel(context.Background())
	defer cancelPeerLoop()
	go serveStalledRenegotiationPeer(peerContext, server, peer, incomingReplies)

	clientLogPath := filepath.Join(workspace.logsDir, "stalled-reneg-client.log")
	dockerClientLogPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "stalled-reneg-client.log"))
	dockerPIDPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "stalled-reneg-client.pid"))
	renderInteropTemplate(t, "tls-client.conf.tmpl", filepath.Join(workspace.renderedDir, "stalled-reneg-client.conf"), tlsClientTemplateData{
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
		AuthFilePath:         filepath.ToSlash(filepath.Join(openVPNInteropRoot, "scripts", "auth-user-pass.txt")),
		LogPath:              dockerClientLogPath,
	})
	clientCommands := []string{
		"openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "stalled-reneg-client.conf")) + " --daemon --writepid " + dockerPIDPath,
		"until grep -q 'Initialization Sequence Completed' " + dockerClientLogPath + "; do sleep 0.1; done",
		"ping -c 1 -W 10 10.8.0.1 > /dev/null 2>&1; sleep 150",
	}
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:       "sing-openvpn-stalled-reneg-client-" + uniqueDockerName(t.Name()),
		Image:      env.image,
		Command:    []string{"bash", "-lc", strings.Join(clientCommands, " && ")},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})
	waitForLogLine(t, clientLogPath, "Initialization Sequence Completed", 40*time.Second)

	peerAddress, peerTunnelAddress := waitForObservedTunnelPeer(t, peer, 30*time.Second)

	renegotiationDeadline := time.Now().Add(stalledRenegotiationInterval + 30*time.Second)
	for authenticationCalls.Load() < 2 {
		if !time.Now().Before(renegotiationDeadline) {
			t.Fatal("the server never renegotiated the key state, so no hand window bounded a key state while the tunnel carried data")
		}
		time.Sleep(interopPollInterval)
	}
	// The renegotiating key_state now holds its hand window open across a
	// deferred authentication; past this instant tls_process would fail that
	// key_state and nothing else.
	time.Sleep(stalledRenegotiationHandWindow + 2*time.Second)

	probe := buildStaticICMPEchoRequest(t,
		netip.MustParseAddr("10.8.0.1"),
		peerTunnelAddress,
		0x5a17,
		1,
		[]byte("stalled-renegotiation-probe"),
	)
	var lastWriteErr error
	probeDeadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(probeDeadline) {
		writeErr := server.WriteDataPacket(peerAddress, probe)
		if writeErr != nil {
			lastWriteErr = writeErr
			time.Sleep(interopPollInterval)
			continue
		}
		replyTimer := time.NewTimer(time.Second)
		select {
		case reply := <-incomingReplies:
			replyTimer.Stop()
			if validateStaticICMPEchoReply(probe, reply) == nil {
				return
			}
		case <-replyTimer.C:
		}
	}
	t.Fatalf("the tunnel stopped carrying data once the renegotiating key state's hand window expired: last write error %v", lastWriteErr)
}

type observedTunnelPeer struct {
	access        sync.Mutex
	address       string
	tunnelAddress netip.Addr
}

func (p *observedTunnelPeer) store(address string, payload []byte) {
	if len(payload) < 20 || payload[0]>>4 != 4 {
		return
	}
	source, sourceValid := netip.AddrFromSlice(payload[12:16])
	if !sourceValid {
		return
	}
	p.access.Lock()
	p.address = address
	p.tunnelAddress = source
	p.access.Unlock()
}

func (p *observedTunnelPeer) load() (string, netip.Addr) {
	p.access.Lock()
	defer p.access.Unlock()
	return p.address, p.tunnelAddress
}

func waitForObservedTunnelPeer(t *testing.T, peer *observedTunnelPeer, timeout time.Duration) (string, netip.Addr) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		address, tunnelAddress := peer.load()
		if address != "" && tunnelAddress.IsValid() {
			return address, tunnelAddress
		}
		time.Sleep(interopPollInterval)
	}
	t.Fatal("the real OpenVPN client never delivered a data packet, so the tunnel never carried data before the renegotiation")
	return "", netip.Addr{}
}

func serveStalledRenegotiationPeer(ctx context.Context, server *openvpn.Server, peer *observedTunnelPeer, replies chan<- []byte) {
	for {
		packet, readErr := server.ReadDataPacket(ctx)
		if readErr != nil {
			return
		}
		peer.store(packet.PeerAddress, packet.Payload)
		reply, replyErr := buildStaticICMPEchoReply(packet.Payload)
		if replyErr == nil {
			_ = server.WriteDataPacket(packet.PeerAddress, reply)
			continue
		}
		select {
		case replies <- append([]byte{}, packet.Payload...):
		default:
		}
	}
}
