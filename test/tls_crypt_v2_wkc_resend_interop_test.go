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
	"github.com/sagernet/sing-openvpn/proto"
)

// Upstream write_outgoing_tls_ciphertext shortens the first reliable control
// packet by the wrapped client key it carries, so a small --max-packet-size
// splits the TLS client hello across a P_CONTROL_WKC_V1 and a P_CONTROL_V1.
type wrappedClientKeyResendPacketConn struct {
	net.PacketConn
	access                     sync.Mutex
	wrappedClientKeyPackets    int
	droppedControlContinuation bool
	droppedAcknowledgment      bool
}

func (c *wrappedClientKeyResendPacketConn) ReadFrom(packet []byte) (int, net.Addr, error) {
	for {
		readCount, remoteAddress, err := c.PacketConn.ReadFrom(packet)
		if readCount == 0 || err != nil {
			return readCount, remoteAddress, err
		}
		c.access.Lock()
		dropped := false
		switch proto.Opcode(packet[0] >> 3) {
		case proto.OpcodeControlWKCv1:
			c.wrappedClientKeyPackets++
		case proto.OpcodeControlV1:
			if !c.droppedControlContinuation {
				c.droppedControlContinuation = true
				dropped = true
			}
		}
		c.access.Unlock()
		if dropped {
			continue
		}
		return readCount, remoteAddress, nil
	}
}

func (c *wrappedClientKeyResendPacketConn) WriteTo(packet []byte, remoteAddress net.Addr) (int, error) {
	if len(packet) > 0 && proto.Opcode(packet[0]>>3) == proto.OpcodeAcknowledgmentV1 {
		c.access.Lock()
		dropped := !c.droppedAcknowledgment
		c.droppedAcknowledgment = true
		c.access.Unlock()
		if dropped {
			return len(packet), nil
		}
	}
	return c.PacketConn.WriteTo(packet, remoteAddress)
}

func (c *wrappedClientKeyResendPacketConn) state() (int, bool, bool) {
	c.access.Lock()
	defer c.access.Unlock()
	return c.wrappedClientKeyPackets, c.droppedControlContinuation, c.droppedAcknowledgment
}

// A P_CONTROL_WKC_V1 packet carries the wrapped client key behind the
// authenticated control packet, and upstream read_control_auth strips it on
// every path before the remainder is authenticated, so a resend of the packet
// stays acceptable after the session already extracted the key.  Dropping the
// second client hello packet forces the client to retransmit its
// P_CONTROL_WKC_V1, and dropping the dedicated P_ACK that acknowledged its
// first transmission leaves that retransmission the only way for the client to
// learn that reliable packet 1 arrived.
func TestOpenVPNInteropTLSCryptV2ResentWrappedClientKeyAuthenticates(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	listenPort := reserveInteropPort(t, "udp")
	packetListener, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", listenPort))
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	lossyListener := &wrappedClientKeyResendPacketConn{PacketConn: packetListener}

	serverContext, cancelServer := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancelServer()
	server, err := openvpn.NewServer(openvpn.ServerOptions{
		NewOutboundQueue: newTestOutboundQueue,
		Context:          serverContext,
		Mode:             openvpn.ModeTLS,
		Transport: openvpn.ServerTransportOptions{
			PacketConn: lossyListener,
			Protocol:   "udp4",
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
			CryptV2:              openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "tls-crypt-v2-server.key")},
			CryptV2ForceCookie:   true,
		},
		Tunnel: openvpn.ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.8.0.2/24")},
			Topology:     "subnet",
		},
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatalf("start server: %v", err)
	}

	tunnelGateway := netip.MustParseAddr("10.8.0.1")
	dockerLogPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "wkc-resend-client.log"))
	dockerConfigurationPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "wkc-resend-client.conf"))
	clientConfiguration := fmt.Sprintf(`proto udp4
remote host.docker.internal %d
nobind
dev tun
client
remote-cert-tls server
ca %s
cert %s
key %s
tls-crypt-v2 %s
max-packet-size 512
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
persist-key
persist-tun
verb 4
log %s
`, listenPort,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.key")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "tls-crypt-v2-client.key")),
		dockerLogPath,
	)
	err = os.WriteFile(filepath.Join(workspace.renderedDir, "wkc-resend-client.conf"), []byte(clientConfiguration), 0o644)
	if err != nil {
		t.Fatalf("write client config: %v", err)
	}
	clientContainer := startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:  "sing-openvpn-wkc-resend-client-" + uniqueDockerName(t.Name()),
		Image: env.image,
		Command: []string{
			"bash",
			"-lc",
			"openvpn --config " + dockerConfigurationPath +
				" --daemon --writepid " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "client.pid")) +
				" && until grep -q 'Initialization Sequence Completed' " + dockerLogPath + "; do sleep 0.1; done" +
				" && ping -c 3 -W 10 " + tunnelGateway.String(),
		},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})

	// The real client keeps retransmitting reliable packet 1 for its whole hand
	// window before it restarts the session with a fresh key, so a server which
	// drops the resent P_CONTROL_WKC_V1 establishes no tunnel within this budget.
	waitForLogLine(t, filepath.Join(workspace.logsDir, "wkc-resend-client.log"), "Initialization Sequence Completed", 30*time.Second)

	wrappedClientKeyPackets, droppedControlContinuation, droppedAcknowledgment := lossyListener.state()
	if !droppedControlContinuation {
		t.Fatal("no P_CONTROL_V1 client hello continuation was dropped")
	}
	if !droppedAcknowledgment {
		t.Fatal("no dedicated P_ACK_V1 was dropped")
	}
	if wrappedClientKeyPackets < 2 {
		t.Fatalf("expected the client to resend its P_CONTROL_WKC_V1, got %d of them", wrappedClientKeyPackets)
	}

	packetContext, cancelPacket := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancelPacket()
	for {
		packet, readErr := server.ReadDataPacket(packetContext)
		if readErr != nil {
			t.Fatalf("read tunnel packet: %v", readErr)
		}
		reply, replyErr := buildStaticICMPEchoReply(packet.Payload)
		if replyErr != nil {
			continue
		}
		writeErr := server.WriteDataPacket(packet.PeerAddress, reply)
		if writeErr != nil {
			t.Fatalf("write tunnel packet: %v", writeErr)
		}
		break
	}
	waitResult := clientContainer.Wait(t, 40*time.Second)
	if waitResult.ExitCode != 0 {
		t.Fatalf("real OpenVPN peer failed: %s", waitResult.Logs)
	}
}
