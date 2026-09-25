package test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
)

// forward.c passes the result of link_socket_read to check_status, which only
// reports the failure, and multi_io.c logs an accept() that produced no socket
// and keeps polling the listen socket. A refused read or a refused accept
// therefore costs upstream neither the established sessions nor the listener.
type transientFailurePacketListener struct {
	net.PacketConn
	pendingFailures atomic.Int64
}

func (c *transientFailurePacketListener) ReadFrom(buffer []byte) (int, net.Addr, error) {
	for {
		pending := c.pendingFailures.Load()
		if pending <= 0 {
			return c.PacketConn.ReadFrom(buffer)
		}
		if c.pendingFailures.CompareAndSwap(pending, pending-1) {
			return 0, nil, &net.OpError{
				Op:     "read",
				Net:    c.PacketConn.LocalAddr().Network(),
				Source: c.PacketConn.LocalAddr(),
				Err:    os.NewSyscallError("recvfrom", syscall.ECONNREFUSED),
			}
		}
	}
}

type transientFailureStreamListener struct {
	net.Listener
	pendingFailures atomic.Int64
}

func (l *transientFailureStreamListener) Accept() (net.Conn, error) {
	for {
		pending := l.pendingFailures.Load()
		if pending <= 0 {
			return l.Listener.Accept()
		}
		if l.pendingFailures.CompareAndSwap(pending, pending-1) {
			return nil, &net.OpError{
				Op:   "accept",
				Net:  l.Listener.Addr().Network(),
				Addr: l.Listener.Addr(),
				Err:  os.NewSyscallError("accept", syscall.ECONNABORTED),
			}
		}
	}
}

func TestOpenVPNInteropServerKeepsServingAfterRefusedDatagramRead(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	listenPort := reserveInteropPort(t, "udp")
	packetListener, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", listenPort))
	if err != nil {
		t.Fatalf("listen refused-read interop socket: %v", err)
	}
	faultyListener := &transientFailurePacketListener{PacketConn: packetListener}
	t.Cleanup(func() {
		_ = packetListener.Close()
	})
	// The first recvfrom fails before the peer has sent a single datagram, so a
	// listener loop that gives up on a read error never observes the handshake.
	faultyListener.pendingFailures.Store(1)

	serverContext, cancelServer := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancelServer()
	server, err := openvpn.NewServer(openvpn.ServerOptions{
		NewOutboundQueue: newTestOutboundQueue,
		Context:          serverContext,
		Mode:             openvpn.ModeTLS,
		Transport: openvpn.ServerTransportOptions{
			PacketConn: faultyListener,
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
		},
	})
	if err != nil {
		t.Fatalf("create refused-read interop server: %v", err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatalf("start refused-read interop server: %v", err)
	}

	peerAddress := netip.MustParseAddr("10.51.0.2")
	tunnelAddress := netip.MustParseAddr("10.51.0.1")
	clientContainer := startInteropTunnelPingClient(t, env, workspace, "refused-read", interopTunnelPingClientOptions{
		Protocol:      "udp4",
		RemotePort:    listenPort,
		PeerAddress:   peerAddress,
		TunnelAddress: tunnelAddress,
		PingCount:     3,
	})

	answerInteropTunnelPings(t, server, 3, 60*time.Second, func(answeredCount int) {
		if answeredCount != 1 {
			return
		}
		// The session is established and carrying traffic: the next read of the
		// shared listener is refused while the peer keeps sending.
		faultyListener.pendingFailures.Store(1)
	})

	waitResult := clientContainer.Wait(t, 40*time.Second)
	if waitResult.ExitCode != 0 {
		t.Fatalf("real OpenVPN peer lost the tunnel across a refused datagram read: %s", waitResult.Logs)
	}
}

func TestOpenVPNInteropServerKeepsAcceptingAfterRefusedAccept(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	listenPort := reserveInteropPort(t, "tcp")
	streamListener, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", listenPort))
	if err != nil {
		t.Fatalf("listen refused-accept interop socket: %v", err)
	}
	faultyListener := &transientFailureStreamListener{Listener: streamListener}
	t.Cleanup(func() {
		_ = streamListener.Close()
	})
	// The first accept fails before the peer has opened a connection, so an
	// accept loop that gives up on an error never admits the real client.
	faultyListener.pendingFailures.Store(1)

	serverContext, cancelServer := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancelServer()
	server, err := openvpn.NewServer(openvpn.ServerOptions{
		NewOutboundQueue: newTestOutboundQueue,
		Context:          serverContext,
		Mode:             openvpn.ModeTLS,
		Transport: openvpn.ServerTransportOptions{
			Listener: faultyListener,
			Protocol: "tcp4",
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
	})
	if err != nil {
		t.Fatalf("create refused-accept interop server: %v", err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatalf("start refused-accept interop server: %v", err)
	}

	peerAddress := netip.MustParseAddr("10.52.0.2")
	tunnelAddress := netip.MustParseAddr("10.52.0.1")
	clientContainer := startInteropTunnelPingClient(t, env, workspace, "refused-accept", interopTunnelPingClientOptions{
		Protocol:      "tcp4-client",
		RemotePort:    listenPort,
		PeerAddress:   peerAddress,
		TunnelAddress: tunnelAddress,
		PingCount:     2,
	})

	answerInteropTunnelPings(t, server, 2, 60*time.Second, nil)

	waitResult := clientContainer.Wait(t, 40*time.Second)
	if waitResult.ExitCode != 0 {
		t.Fatalf("real OpenVPN peer never reached the listener after a refused accept: %s", waitResult.Logs)
	}
}

type interopTunnelPingClientOptions struct {
	Protocol      string
	RemotePort    int
	PeerAddress   netip.Addr
	TunnelAddress netip.Addr
	PingCount     int
}

func startInteropTunnelPingClient(
	t *testing.T,
	env interopEnvironment,
	workspace interopWorkspace,
	name string,
	options interopTunnelPingClientOptions,
) *interopContainer {
	t.Helper()
	dockerLogPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", name+"-client.log"))
	dockerConfigurationPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", name+"-client.conf"))
	clientConfiguration := fmt.Sprintf(`proto %s
remote host.docker.internal %d
nobind
dev tun
client
remote-cert-tls server
ca %s
cert %s
key %s
ifconfig %s %s
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
persist-key
persist-tun
verb 4
log %s
`, options.Protocol, options.RemotePort,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.key")),
		options.PeerAddress,
		options.TunnelAddress,
		dockerLogPath,
	)
	err := os.WriteFile(filepath.Join(workspace.renderedDir, name+"-client.conf"), []byte(clientConfiguration), 0o644)
	if err != nil {
		t.Fatalf("write %s client configuration: %v", name, err)
	}
	return startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:  "sing-openvpn-" + name + "-client-" + uniqueDockerName(t.Name()),
		Image: env.image,
		Command: []string{
			"bash",
			"-lc",
			"openvpn --config " + dockerConfigurationPath +
				" --daemon --writepid " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "client.pid")) +
				" && until grep -q 'Outgoing Data Channel: Cipher' " + dockerLogPath + "; do sleep 0.1; done" +
				fmt.Sprintf(" && ping -c %d -W 10 ", options.PingCount) + options.TunnelAddress.String(),
		},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})
}

func answerInteropTunnelPings(
	t *testing.T,
	server *openvpn.Server,
	requestCount int,
	timeout time.Duration,
	afterAnswer func(answeredCount int),
) {
	t.Helper()
	packetContext, cancelPacket := context.WithTimeout(context.Background(), timeout)
	defer cancelPacket()
	answeredCount := 0
	for answeredCount < requestCount {
		packet, readErr := server.ReadDataPacket(packetContext)
		if readErr != nil {
			t.Fatalf("read tunnel echo request %d of %d: %v", answeredCount+1, requestCount, readErr)
		}
		reply, replyErr := buildStaticICMPEchoReply(packet.Payload)
		if replyErr != nil {
			continue
		}
		writeErr := server.WriteDataPacket(packet.PeerAddress, reply)
		if writeErr != nil {
			t.Fatalf("write tunnel echo reply %d of %d: %v", answeredCount+1, requestCount, writeErr)
		}
		answeredCount++
		if afterAnswer != nil {
			afterAnswer(answeredCount)
		}
	}
}
