package test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	"github.com/sagernet/sing-openvpn/proto"
	E "github.com/sagernet/sing/common/exceptions"
)

// process_incoming_link_part1 (forward.c) registers SIGUSR1 with "Fatal
// decryption error (process_incoming_link), restarting" when openvpn_decrypt
// fails while link_socket_connection_oriented holds, so a stream peer whose
// data channel stops authenticating restarts the connection instead of reading
// the stream on.
type corruptingFrameConn struct {
	net.Conn
	access        sync.Mutex
	readBuffer    []byte
	pendingStream []byte
	readyFrames   []byte
	armed         atomic.Bool
	corrupted     atomic.Bool
	closed        atomic.Bool
}

func (c *corruptingFrameConn) Arm() {
	c.armed.Store(true)
}

func (c *corruptingFrameConn) Corrupted() bool {
	return c.corrupted.Load()
}

func (c *corruptingFrameConn) Closed() bool {
	return c.closed.Load()
}

func (c *corruptingFrameConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func (c *corruptingFrameConn) Read(packet []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	for {
		if len(c.readyFrames) > 0 {
			n := copy(packet, c.readyFrames)
			c.readyFrames = c.readyFrames[n:]
			return n, nil
		}
		n, err := c.Conn.Read(c.readBuffer)
		if n > 0 {
			c.pendingStream = append(c.pendingStream, c.readBuffer[:n]...)
			c.extractFrames()
		}
		if len(c.readyFrames) > 0 {
			continue
		}
		if err != nil {
			return 0, err
		}
	}
}

func (c *corruptingFrameConn) extractFrames() {
	for len(c.pendingStream) >= 2 {
		frameLength := int(binary.BigEndian.Uint16(c.pendingStream[:2]))
		if len(c.pendingStream) < 2+frameLength {
			return
		}
		frame := c.pendingStream[:2+frameLength]
		c.pendingStream = c.pendingStream[2+frameLength:]
		if frameLength > 0 && c.armed.Load() && !c.corrupted.Load() {
			opcode := proto.Opcode(frame[2] >> 3)
			if opcode == proto.OpcodeDataV1 || opcode == proto.OpcodeDataV2 {
				corruptedFrame := append([]byte{}, frame...)
				corruptedFrame[len(corruptedFrame)-1] ^= 0xff
				c.corrupted.Store(true)
				c.readyFrames = append(c.readyFrames, corruptedFrame...)
				continue
			}
		}
		c.readyFrames = append(c.readyFrames, frame...)
	}
}

type corruptingFrameListener struct {
	net.Listener
	access sync.Mutex
	links  []*corruptingFrameConn
}

func (l *corruptingFrameListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	link := &corruptingFrameConn{Conn: conn, readBuffer: make([]byte, 65535)}
	l.access.Lock()
	l.links = append(l.links, link)
	l.access.Unlock()
	return link, nil
}

func (l *corruptingFrameListener) lastLink() *corruptingFrameConn {
	l.access.Lock()
	defer l.access.Unlock()
	if len(l.links) == 0 {
		return nil
	}
	return l.links[len(l.links)-1]
}

func TestOpenVPNInteropTCPDataDecryptionErrorRestartsClientSession(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	serverPort := reserveInteropPort(t, "tcp")
	serverConfiguration := fmt.Sprintf(`port %d
proto tcp4-server
dev tun
topology subnet
server 10.57.0.0 255.255.255.0
ca %s
cert %s
key %s
dh none
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
keepalive 60 300
persist-key
persist-tun
verb 4
log %s
`, serverPort,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "decrypt-error-server.log")),
	)
	serverConfigurationPath := filepath.Join(workspace.renderedDir, "decrypt-error-server.conf")
	err := os.WriteFile(serverConfigurationPath, []byte(serverConfiguration), 0o644)
	if err != nil {
		t.Fatalf("write decryption error server config: %v", err)
	}
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-decrypt-error-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"openvpn", "--config", filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "decrypt-error-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: tcpPortBinding(serverPort),
		Privileged:   true,
	})
	waitForLogLine(t, filepath.Join(workspace.logsDir, "decrypt-error-server.log"), "Initialization Sequence Completed", 20*time.Second)

	var linkAccess sync.Mutex
	var links []*corruptingFrameConn
	dialContext := func(ctx context.Context, network string, address string) (net.Conn, error) {
		if !strings.HasPrefix(network, "tcp") {
			return nil, E.New("unsupported network: ", network)
		}
		conn, dialErr := (&net.Dialer{}).DialContext(ctx, network, address)
		if dialErr != nil {
			return nil, dialErr
		}
		link := &corruptingFrameConn{Conn: conn, readBuffer: make([]byte, 65535)}
		linkAccess.Lock()
		links = append(links, link)
		linkAccess.Unlock()
		return link, nil
	}
	dialedLinks := func() (int, *corruptingFrameConn) {
		linkAccess.Lock()
		defer linkAccess.Unlock()
		if len(links) == 0 {
			return 0, nil
		}
		return len(links), links[len(links)-1]
	}

	clientContext, cancelClient := context.WithTimeout(context.Background(), 120*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context: clientContext,
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ClientTransportOptions{
			Remotes:     []openvpn.Remote{clientRemote(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), "tcp4")},
			DialContext: dialContext,
			Protocol:    "tcp4",
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
		Pull:   openvpn.ClientPullOptions{Enabled: true},
		Timing: openvpn.ClientTimingOptions{HandWindow: 10 * time.Second},
	})
	if err != nil {
		cancelClient()
		t.Fatalf("create decryption error interop client: %v", err)
	}
	t.Cleanup(func() {
		cancelClient()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close decryption error interop client: %v", closeErr)
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatalf("start decryption error interop client: %v", err)
	}

	configuration := waitForClientIfconfig(t, client, 20*time.Second)
	localAddress := configuration.LocalIPv4[0].Addr()
	remoteAddress := netip.MustParseAddr("10.57.0.1")
	establishedRequest := buildStaticICMPEchoRequest(t, localAddress, remoteAddress, 0x5701, 1, bytes.Repeat([]byte{0x27}, 64))
	writeClientDataPacket(t, client, establishedRequest, 20*time.Second)
	awaitClientICMPEchoReply(t, client, establishedRequest, 20*time.Second)

	establishedLinkCount, establishedLink := dialedLinks()
	if establishedLink == nil {
		t.Fatal("the established session did not run over the instrumented link")
	}
	establishedLink.Arm()

	corruptedRequest := buildStaticICMPEchoRequest(t, localAddress, remoteAddress, 0x5701, 2, bytes.Repeat([]byte{0x27}, 64))
	writeClientDataPacket(t, client, corruptedRequest, 20*time.Second)
	corruptionDeadline := time.Now().Add(20 * time.Second)
	for !establishedLink.Corrupted() {
		if !time.Now().Before(corruptionDeadline) {
			t.Fatal("no data channel packet reached the client over the instrumented link")
		}
		time.Sleep(interopPollInterval)
	}

	restartDeadline := time.Now().Add(45 * time.Second)
	for {
		linkCount, _ := dialedLinks()
		if linkCount > establishedLinkCount {
			break
		}
		if !time.Now().Before(restartDeadline) {
			t.Fatal("the client kept the stream session after a data packet failed to decrypt")
		}
		time.Sleep(interopPollInterval)
	}

	for !client.Ready() {
		if !time.Now().Before(restartDeadline) {
			t.Fatal("the client did not re-establish the tunnel after the fatal decryption error")
		}
		time.Sleep(interopPollInterval)
	}
	restartedConfiguration := client.TunnelConfiguration()
	if len(restartedConfiguration.LocalIPv4) == 0 {
		t.Fatal("the re-established tunnel carries no pushed ifconfig")
	}
	restartedLocalAddress := restartedConfiguration.LocalIPv4[0].Addr()
	restartedRequest := buildStaticICMPEchoRequest(t, restartedLocalAddress, remoteAddress, 0x5701, 3, bytes.Repeat([]byte{0x27}, 64))
	writeClientDataPacket(t, client, restartedRequest, 30*time.Second)
	awaitClientICMPEchoReply(t, client, restartedRequest, 30*time.Second)
}

func TestOpenVPNInteropTCPDataDecryptionErrorClosesServerSession(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	listenPort := reserveInteropPort(t, "tcp")
	streamListener, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", listenPort))
	if err != nil {
		t.Fatalf("listen decryption error interop socket: %v", err)
	}
	corruptingListener := &corruptingFrameListener{Listener: streamListener}
	t.Cleanup(func() {
		_ = streamListener.Close()
	})

	serverContext, cancelServer := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancelServer()
	server, err := openvpn.NewServer(openvpn.ServerOptions{
		NewOutboundQueue: newTestOutboundQueue,
		Context:          serverContext,
		Mode:             openvpn.ModeTLS,
		Transport: openvpn.ServerTransportOptions{
			Listener: corruptingListener,
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
		t.Fatalf("create decryption error interop server: %v", err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatalf("start decryption error interop server: %v", err)
	}

	peerAddress := netip.MustParseAddr("10.58.0.2")
	tunnelAddress := netip.MustParseAddr("10.58.0.1")
	// The peer keeps pinging for the whole observation window, so the link this
	// test watches is closed by the server or not at all.
	startInteropTunnelPingClient(t, env, workspace, "decrypt-error", interopTunnelPingClientOptions{
		Protocol:      "tcp4-client",
		RemotePort:    listenPort,
		PeerAddress:   peerAddress,
		TunnelAddress: tunnelAddress,
		PingCount:     120,
	})

	var establishedLink *corruptingFrameConn
	answerInteropTunnelPings(t, server, 1, 60*time.Second, func(_ int) {
		establishedLink = corruptingListener.lastLink()
		if establishedLink == nil {
			t.Error("the established session did not run over the instrumented link")
			return
		}
		establishedLink.Arm()
	})
	if establishedLink == nil {
		t.Fatal("the established session did not run over the instrumented link")
	}

	corruptionDeadline := time.Now().Add(30 * time.Second)
	for !establishedLink.Corrupted() {
		if !time.Now().Before(corruptionDeadline) {
			t.Fatal("no data channel packet reached the server over the instrumented link")
		}
		time.Sleep(interopPollInterval)
	}
	closeDeadline := time.Now().Add(20 * time.Second)
	for !establishedLink.Closed() {
		if !time.Now().Before(closeDeadline) {
			t.Fatal("the server kept the stream session after a data packet failed to decrypt")
		}
		time.Sleep(interopPollInterval)
	}
	waitForAnyLogLine(t, filepath.Join(workspace.logsDir, "decrypt-error-client.log"), []string{
		"Connection reset, restarting",
		"SIGUSR1[soft,connection-reset]",
	}, 20*time.Second)
}
