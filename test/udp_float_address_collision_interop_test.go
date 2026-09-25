package test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
)

// multi_process_float (multi.c) refuses a float only when the instance already
// holding the address presents a different locked certificate chain; otherwise
// it closes that instance and hands the address to the peer that authenticated
// on it, so a NAT rebinding onto an address a stale session still owns keeps the
// floated peer's tunnel carrying traffic.
func TestOpenVPNInteropUDPFloatOntoAddressHeldByStaleSessionKeepsFloatedPeerConnected(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	marksDir := filepath.Join(workspace.root, "marks")
	err := os.MkdirAll(marksDir, 0o755)
	if err != nil {
		t.Fatalf("create interop marker directory: %v", err)
	}
	dockerMarksDir := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "marks"))

	serverListener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen float collision server socket: %v", err)
	}
	t.Cleanup(func() {
		_ = serverListener.Close()
	})
	peerPort := reserveInteropPort(t, "udp")
	firstSourcePort := reserveInteropPort(t, "udp")
	secondSourcePort := reserveInteropPort(t, "udp")
	relay := startFloatNATRelay(t, peerPort, firstSourcePort, serverListener.LocalAddr())

	serverContext, cancelServer := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancelServer()
	server, err := openvpn.NewServer(openvpn.ServerOptions{
		NewOutboundQueue: newTestOutboundQueue,
		Context:          serverContext,
		Mode:             openvpn.ModeTLS,
		Transport: openvpn.ServerTransportOptions{
			PacketConn: serverListener,
			Protocol:   "udp4",
		},
		DataChannel: openvpn.ServerDataChannelOptions{
			Ciphers: []string{"AES-256-GCM"},
		},
		TLS: openvpn.ServerTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		// The abandoned session keeps its source address registered because
		// nothing expires it, which is the state a floating peer collides with.
		Authentication: openvpn.ServerAuthenticationOptions{DuplicateCN: true},
		Tunnel: openvpn.ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")},
			Topology:     "subnet",
		},
	})
	if err != nil {
		t.Fatalf("create float collision server: %v", err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatalf("start float collision server: %v", err)
	}

	firstConfigurationPath, firstLogPath := renderFloatCollisionClient(t, workspace, "float-collision-first", peerPort)
	secondConfigurationPath, secondLogPath := renderFloatCollisionClient(t, workspace, "float-collision-second", peerPort)
	firstPIDPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "float-collision-first.pid"))
	secondPIDPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "float-collision-second.pid"))
	startClient := func(configurationPath string, logPath string, pidPath string) string {
		return "openvpn --config " + configurationPath + " --daemon --writepid " + pidPath +
			" && until grep -q 'Initialization Sequence Completed' " + logPath + "; do sleep 0.1; done"
	}
	clientContainer := startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:  "sing-openvpn-float-collision-client-" + uniqueDockerName(t.Name()),
		Image: env.image,
		Command: []string{
			"bash",
			"-lc",
			startClient(firstConfigurationPath, firstLogPath, firstPIDPath) +
				" && ping -c 2 -W 15 10.9.0.1" +
				" && kill -9 \"$(cat " + firstPIDPath + ")\"" +
				" && touch " + dockerMarksDir + "/first-abandoned" +
				" && until [ -f " + dockerMarksDir + "/relay-moved ]; do sleep 0.1; done" +
				" && " + startClient(secondConfigurationPath, secondLogPath, secondPIDPath) +
				" && ping -c 2 -W 15 10.9.0.1" +
				" && touch " + dockerMarksDir + "/second-established" +
				" && until [ -f " + dockerMarksDir + "/relay-collided ]; do sleep 0.1; done" +
				" && ping -c 3 -W 25 10.9.0.1",
		},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})

	answerInteropTunnelPings(t, server, 2, 60*time.Second, nil)
	waitForFile(t, filepath.Join(marksDir, "first-abandoned"), 30*time.Second)
	relay.BindSourcePort(t, secondSourcePort)
	writeInteropMarker(t, marksDir, "relay-moved")

	answerInteropTunnelPings(t, server, 2, 60*time.Second, nil)
	waitForFile(t, filepath.Join(marksDir, "second-established"), 30*time.Second)
	relay.BindSourcePort(t, firstSourcePort)
	writeInteropMarker(t, marksDir, "relay-collided")

	answerInteropTunnelPings(t, server, 3, 60*time.Second, nil)
	waitResult := clientContainer.Wait(t, 60*time.Second)
	if waitResult.ExitCode != 0 {
		t.Fatalf("real OpenVPN peer lost the tunnel after floating onto a held address: %s", waitResult.Logs)
	}
}

func renderFloatCollisionClient(t *testing.T, workspace interopWorkspace, name string, peerPort int) (string, string) {
	t.Helper()
	dockerLogPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", name+".log"))
	renderInteropTemplate(t, "tls-client.conf.tmpl", filepath.Join(workspace.renderedDir, name+".conf"), tlsClientTemplateData{
		Protocol:             "udp4",
		RemoteHost:           "host.docker.internal",
		RemotePort:           peerPort,
		CAPath:               filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		CertPath:             filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.crt")),
		KeyPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.key")),
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          "AES-256-GCM",
		LogPath:              dockerLogPath,
	})
	return filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", name+".conf")), dockerLogPath
}

func writeInteropMarker(t *testing.T, marksDir string, name string) {
	t.Helper()
	err := os.WriteFile(filepath.Join(marksDir, name), nil, 0o644)
	if err != nil {
		t.Fatalf("write interop marker %s: %v", name, err)
	}
}

// The relay owns the source address the server learns for the containerized
// peer, so rebinding it to a port an earlier session still occupies reproduces a
// NAT rebinding onto an address the server has already handed out.
type floatNATRelay struct {
	peerFacing    net.PacketConn
	serverAddress net.Addr
	access        sync.Mutex
	serverFacing  net.PacketConn
	peerAddress   net.Addr
}

func startFloatNATRelay(t *testing.T, peerPort int, sourcePort int, serverAddress net.Addr) *floatNATRelay {
	t.Helper()
	peerFacing, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", peerPort))
	if err != nil {
		t.Fatalf("listen float relay peer socket: %v", err)
	}
	relay := &floatNATRelay{
		peerFacing:    peerFacing,
		serverAddress: serverAddress,
	}
	t.Cleanup(func() {
		_ = peerFacing.Close()
		relay.access.Lock()
		serverFacing := relay.serverFacing
		relay.serverFacing = nil
		relay.access.Unlock()
		if serverFacing != nil {
			_ = serverFacing.Close()
		}
	})
	relay.BindSourcePort(t, sourcePort)
	go relay.forwardToServer()
	return relay
}

func (r *floatNATRelay) BindSourcePort(t *testing.T, sourcePort int) {
	t.Helper()
	r.access.Lock()
	previous := r.serverFacing
	r.serverFacing = nil
	r.access.Unlock()
	if previous != nil {
		_ = previous.Close()
	}
	serverFacing, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", sourcePort))
	if err != nil {
		t.Fatalf("bind float relay source port %d: %v", sourcePort, err)
	}
	r.access.Lock()
	r.serverFacing = serverFacing
	r.access.Unlock()
	go r.forwardToPeer(serverFacing)
}

func (r *floatNATRelay) forwardToServer() {
	buffer := make([]byte, 65535)
	for {
		dataLength, source, err := r.peerFacing.ReadFrom(buffer)
		if err != nil {
			return
		}
		r.access.Lock()
		r.peerAddress = source
		serverFacing := r.serverFacing
		r.access.Unlock()
		if serverFacing == nil {
			continue
		}
		_, _ = serverFacing.WriteTo(buffer[:dataLength], r.serverAddress)
	}
}

func (r *floatNATRelay) forwardToPeer(serverFacing net.PacketConn) {
	buffer := make([]byte, 65535)
	for {
		dataLength, _, err := serverFacing.ReadFrom(buffer)
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
