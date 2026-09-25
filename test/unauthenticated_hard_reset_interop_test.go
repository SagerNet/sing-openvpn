package test

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	"github.com/sagernet/sing-openvpn/proto"
)

// tls_pre_decrypt (ssl.c) matches every incoming hard reset against the session
// ids its tls_multi holds before anything happens to it, and one which matches
// none of them opens a fresh TM_INITIAL tls_session while TM_ACTIVE keeps
// carrying the tunnel until that new session authenticates.  Without
// tls-auth/tls-crypt read_control_auth authenticates nothing, so a single forged
// or stale reset datagram from the address a peer is served on must still leave
// its tunnel serving.
func TestOpenVPNInteropUDPUnauthenticatedHardResetKeepsEstablishedTunnelServing(t *testing.T) {
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
		t.Fatalf("listen hard reset server socket: %v", err)
	}
	t.Cleanup(func() {
		_ = serverListener.Close()
	})
	peerPort := reserveInteropPort(t, "udp")
	relay := startHardResetInjectionRelay(t, peerPort, serverListener.LocalAddr())

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
		Tunnel: openvpn.ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.11.0.0/24")},
			Topology:     "subnet",
		},
	})
	if err != nil {
		t.Fatalf("create hard reset server: %v", err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatalf("start hard reset server: %v", err)
	}

	name := "unauthenticated-hard-reset-client"
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
	dockerConfigurationPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", name+".conf"))
	dockerPIDPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, name+".pid"))
	clientContainer := startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:  "sing-openvpn-hard-reset-client-" + uniqueDockerName(t.Name()),
		Image: env.image,
		Command: []string{
			"bash",
			"-lc",
			"openvpn --config " + dockerConfigurationPath + " --daemon --writepid " + dockerPIDPath +
				" && until grep -q 'Initialization Sequence Completed' " + dockerLogPath + "; do sleep 0.1; done" +
				" && ping -c 2 -W 20 10.11.0.1" +
				" && touch " + dockerMarksDir + "/established" +
				" && until [ -f " + dockerMarksDir + "/reset-injected ]; do sleep 0.1; done" +
				" && ping -c 6 -W 20 10.11.0.1",
		},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})

	answerInteropTunnelPings(t, server, 2, 60*time.Second, nil)
	waitForFile(t, filepath.Join(marksDir, "established"), 30*time.Second)
	relay.InjectClientHardReset(t)
	writeInteropMarker(t, marksDir, "reset-injected")

	answerInteropTunnelPings(t, server, 2, 45*time.Second, nil)
	waitResult := clientContainer.Wait(t, 60*time.Second)
	if waitResult.ExitCode != 0 {
		t.Fatalf("real OpenVPN peer lost its tunnel after an unauthenticated hard reset: %s", waitResult.Logs)
	}
}

// The relay owns the source address the server learns for the containerized
// peer, so a datagram it sends on its own reaches the server as one more
// datagram from that peer.
type hardResetInjectionRelay struct {
	peerFacing    net.PacketConn
	serverFacing  net.PacketConn
	serverAddress net.Addr
	access        sync.Mutex
	peerAddress   net.Addr
}

func startHardResetInjectionRelay(t *testing.T, peerPort int, serverAddress net.Addr) *hardResetInjectionRelay {
	t.Helper()
	peerFacing, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", peerPort))
	if err != nil {
		t.Fatalf("listen hard reset relay peer socket: %v", err)
	}
	serverFacing, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = peerFacing.Close()
		t.Fatalf("listen hard reset relay server socket: %v", err)
	}
	relay := &hardResetInjectionRelay{
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

func (r *hardResetInjectionRelay) InjectClientHardReset(t *testing.T) {
	t.Helper()
	var forgedSessionID proto.SessionID
	_, err := rand.Read(forgedSessionID[:])
	if err != nil {
		t.Fatalf("generate forged session id: %v", err)
	}
	forgedReset := &proto.Packet{
		Opcode:         proto.OpcodeControlHardResetClientV2,
		KeyID:          0,
		LocalSessionID: forgedSessionID,
		ID:             0,
	}
	rawPacket, err := forgedReset.Bytes()
	if err != nil {
		t.Fatalf("serialize forged hard reset: %v", err)
	}
	_, err = r.serverFacing.WriteTo(rawPacket, r.serverAddress)
	if err != nil {
		t.Fatalf("inject forged hard reset: %v", err)
	}
}

func (r *hardResetInjectionRelay) forwardToServer() {
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

func (r *hardResetInjectionRelay) forwardToPeer() {
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
