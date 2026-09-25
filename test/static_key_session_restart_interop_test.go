package test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
)

// A ping-restart of a --secret peer takes the SIGUSR1 path of openvpn.c, which
// re-enters the tunnel over the unchanged --lport: the peer that resumes
// sending after the restart reaches the same datagram endpoint and is answered.
func TestOpenVPNInteropStaticKeyServerKeepsListeningAcrossSessionRestart(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	peerPort := reserveInteropPort(t, "udp")
	serverListener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen static_key interop socket: %v", err)
	}
	t.Cleanup(func() {
		_ = serverListener.Close()
	})
	relay := startStaticKeyPeerRelay(t, peerPort, serverListener.LocalAddr())

	serverContext, cancelServer := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancelServer()
	server, err := openvpn.NewServer(openvpn.ServerOptions{
		NewOutboundQueue: newTestOutboundQueue,
		Context:          serverContext,
		Mode:             openvpn.ModeStaticKey,
		Transport: openvpn.ServerTransportOptions{
			PacketConn:    serverListener,
			RemoteAddress: relay.serverFacing.LocalAddr().String(),
			Protocol:      "udp4",
		},
		DataChannel: openvpn.ServerDataChannelOptions{
			Cipher: "AES-256-CBC",
			Auth:   "SHA256",
		},
		Tunnel: openvpn.ServerTunnelOptions{
			LocalAddress: []netip.Prefix{netip.MustParsePrefix("10.53.0.1/32")},
			VPNGateway:   netip.MustParseAddr("10.53.0.2"),
		},
		// The peer stops sending for longer than PingRestart, which ends the
		// session that owns the tunnel while the bound socket must survive.
		Timing: openvpn.ServerTimingOptions{
			PingInterval: time.Second,
			PingRestart:  5 * time.Second,
		},
		StaticKey:    openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "static.key")},
		KeyDirection: 0,
	})
	if err != nil {
		t.Fatalf("create static_key interop server: %v", err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatalf("start static_key interop server: %v", err)
	}

	peerContainer := startStaticKeyRestartPeer(t, env, workspace, peerPort)
	answerInteropTunnelPings(t, server, 2, 60*time.Second, nil)
	answerInteropTunnelPings(t, server, 2, 60*time.Second, nil)

	waitResult := peerContainer.Wait(t, 60*time.Second)
	if waitResult.ExitCode != 0 {
		t.Fatalf("real OpenVPN --secret peer lost the server across a session restart: %s", waitResult.Logs)
	}
}

func startStaticKeyRestartPeer(
	t *testing.T,
	env interopEnvironment,
	workspace interopWorkspace,
	peerPort int,
) *interopContainer {
	t.Helper()
	renderPeer := func(name string) (string, string) {
		dockerLogPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", name+".log"))
		renderInteropTemplate(t, "static-peer.conf.tmpl", filepath.Join(workspace.renderedDir, name+".conf"), staticPeerTemplateData{
			Protocol:     "udp4",
			RemoteHost:   "host.docker.internal",
			RemotePort:   peerPort,
			UseNobind:    true,
			TunnelLocal:  "10.53.0.2",
			TunnelRemote: "10.53.0.1",
			SecretPath:   filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "static.key")),
			KeyDirection: 1,
			Cipher:       "AES-256-CBC",
			Auth:         "SHA256",
			LogPath:      dockerLogPath,
		})
		return filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", name+".conf")), dockerLogPath
	}
	firstConfigurationPath, firstLogPath := renderPeer("static-restart-peer-first")
	secondConfigurationPath, secondLogPath := renderPeer("static-restart-peer-second")
	pidPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "static-restart-peer.pid"))
	startPeer := func(configurationPath string, logPath string) string {
		return "openvpn --config " + configurationPath + " --ping 1 --daemon --writepid " + pidPath +
			" && until grep -q 'Initialization Sequence Completed' " + logPath + "; do sleep 0.1; done"
	}
	return startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:  "sing-openvpn-static-restart-peer-" + uniqueDockerName(t.Name()),
		Image: env.image,
		Command: []string{
			"bash",
			"-lc",
			startPeer(firstConfigurationPath, firstLogPath) +
				" && ping -c 2 -W 15 10.53.0.1" +
				" && kill \"$(cat " + pidPath + ")\"" +
				" && sleep 8" +
				" && " + startPeer(secondConfigurationPath, secondLogPath) +
				" && ping -c 2 -W 20 10.53.0.1",
		},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})
}

// The relay pins the source address the static-key server sees, which upstream
// takes from --remote: the containerized peer reaches the host through a NAT
// address that no configuration can name in advance.
type staticKeyPeerRelay struct {
	peerFacing    net.PacketConn
	serverFacing  net.PacketConn
	serverAddress net.Addr
	access        sync.Mutex
	peerAddress   net.Addr
}

func startStaticKeyPeerRelay(t *testing.T, peerPort int, serverAddress net.Addr) *staticKeyPeerRelay {
	t.Helper()
	peerFacing, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", peerPort))
	if err != nil {
		t.Fatalf("listen static_key peer relay socket: %v", err)
	}
	serverFacing, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = peerFacing.Close()
		t.Fatalf("listen static_key server relay socket: %v", err)
	}
	relay := &staticKeyPeerRelay{
		peerFacing:    peerFacing,
		serverFacing:  serverFacing,
		serverAddress: serverAddress,
	}
	t.Cleanup(func() {
		_ = peerFacing.Close()
		_ = serverFacing.Close()
	})
	go relay.forwardToServer()
	go relay.forwardToPeer()
	return relay
}

func (r *staticKeyPeerRelay) forwardToServer() {
	buffer := make([]byte, 65535)
	for {
		dataLength, source, err := r.peerFacing.ReadFrom(buffer)
		if err != nil {
			return
		}
		r.access.Lock()
		r.peerAddress = source
		r.access.Unlock()
		_, _ = r.serverFacing.WriteTo(buffer[:dataLength], r.serverAddress)
	}
}

func (r *staticKeyPeerRelay) forwardToPeer() {
	buffer := make([]byte, 65535)
	for {
		dataLength, _, err := r.serverFacing.ReadFrom(buffer)
		if err != nil {
			return
		}
		r.access.Lock()
		peerAddress := r.peerAddress
		r.access.Unlock()
		if peerAddress == nil {
			continue
		}
		_, _ = r.peerFacing.WriteTo(buffer[:dataLength], peerAddress)
	}
}
