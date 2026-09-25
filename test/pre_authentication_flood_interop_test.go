package test

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	"github.com/sagernet/sing-openvpn/proto"
)

const (
	preAuthenticationBurstSessions    = 120
	preAuthenticationBurstReplyWait   = 250 * time.Millisecond
	preAuthenticationBurstMaximumTime = 8 * time.Second
	preAuthenticationJunkInterval     = 3 * time.Millisecond
)

func TestOpenVPNInteropServerAdmitsNewClientDuringUnauthenticatedPreAuthenticationFlood(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	listenPort := reserveInteropPort(t, "udp")
	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancelServerContext()
	var authenticationCount atomic.Uint32
	server, err := openvpn.NewServer(openvpn.ServerOptions{
		NewOutboundQueue: newTestOutboundQueue,
		Context:          serverContext,
		Mode:             openvpn.ModeTLS,
		Transport: openvpn.ServerTransportOptions{
			ListenAddress: fmt.Sprintf("0.0.0.0:%d", listenPort),
			Protocol:      "udp4",
		},
		DataChannel: openvpn.ServerDataChannelOptions{
			Ciphers: []string{"AES-256-GCM", "AES-128-GCM"},
		},
		TLS: openvpn.ServerTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Authentication: openvpn.ServerAuthenticationOptions{Authenticator: func(_ context.Context, username string, password string) error {
			if username != "test-user" || password != "test-password" {
				return openvpn.ErrAuthenticationFailed
			}
			authenticationCount.Add(1)
			return nil
		}},
		Tunnel: openvpn.ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
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

	serverAddress := net.JoinHostPort("127.0.0.1", fmt.Sprint(listenPort))
	stopJunk := startUnauthenticatedCookieResponseFlood(t, serverAddress)
	defer stopJunk()

	burstStart := time.Now()
	answered := runPreAuthenticationHandshakeBurst(t, serverAddress, preAuthenticationBurstSessions)
	burstDuration := time.Since(burstStart)
	if burstDuration > preAuthenticationBurstMaximumTime {
		t.Fatalf("pre-authentication burst of %d handshakes took %s, which no longer fits a single rate-limit window",
			preAuthenticationBurstSessions, burstDuration)
	}
	if answered != preAuthenticationBurstSessions {
		t.Fatalf("server answered %d of %d pre-authentication handshakes within %s",
			answered, preAuthenticationBurstSessions, burstDuration)
	}

	clientLogPath := filepath.Join(workspace.logsDir, "pre-auth-flood-client.log")
	renderInteropTemplate(t, "tls-client.conf.tmpl", filepath.Join(workspace.renderedDir, "pre-auth-flood-client.conf"), tlsClientTemplateData{
		Protocol:             "udp4",
		RemoteHost:           "host.docker.internal",
		RemotePort:           listenPort,
		CAPath:               filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		CertPath:             filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.crt")),
		KeyPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.key")),
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          strings.Join([]string{"AES-256-GCM", "AES-128-GCM"}, ":"),
		AuthFilePath:         filepath.ToSlash(filepath.Join(openVPNInteropRoot, "scripts", "auth-user-pass.txt")),
		LogPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "pre-auth-flood-client.log")),
	})
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:       "sing-openvpn-pre-auth-flood-client-" + uniqueDockerName(t.Name()),
		Image:      env.image,
		Command:    []string{"bash", "-lc", "exec openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "pre-auth-flood-client.conf"))},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})
	waitForAuthenticationCount(t, &authenticationCount, 1, 35*time.Second)
	waitForLogLine(t, clientLogPath, "Initialization Sequence Completed", 35*time.Second)
}

// Upstream admits a UDP session only after the stateless three-way exchange:
// P_CONTROL_HARD_RESET_CLIENT_V2, the server's HMAC session-id reply, and a
// P_ACK_V1 quoting that session id back as its remote session id.
func runPreAuthenticationHandshakeBurst(t *testing.T, serverAddress string, count int) int {
	t.Helper()
	answered := 0
	replyBuffer := make([]byte, 1500)
	for probeIndex := range count {
		probeConnection, dialErr := net.Dial("udp4", serverAddress)
		if dialErr != nil {
			t.Fatalf("dial pre-authentication probe %d: %v", probeIndex, dialErr)
		}
		t.Cleanup(func() {
			_ = probeConnection.Close()
		})
		var clientSessionID proto.SessionID
		_, err := rand.Read(clientSessionID[:])
		if err != nil {
			t.Fatalf("generate probe session id: %v", err)
		}
		resetPacket := &proto.Packet{
			Opcode:         proto.OpcodeControlHardResetClientV2,
			LocalSessionID: clientSessionID,
		}
		resetBytes, err := resetPacket.Bytes()
		if err != nil {
			t.Fatalf("serialize probe reset: %v", err)
		}
		_, err = probeConnection.Write(resetBytes)
		if err != nil {
			t.Fatalf("write probe reset %d: %v", probeIndex, err)
		}
		err = probeConnection.SetReadDeadline(time.Now().Add(preAuthenticationBurstReplyWait))
		if err != nil {
			t.Fatalf("set probe read deadline: %v", err)
		}
		readCount, err := probeConnection.Read(replyBuffer)
		if err != nil {
			continue
		}
		reply, err := proto.ParsePacket(replyBuffer[:readCount])
		if err != nil || reply.Opcode != proto.OpcodeControlHardResetServerV2 || reply.RemoteSessionID != clientSessionID {
			continue
		}
		acknowledgmentPacket := &proto.Packet{
			Opcode:            proto.OpcodeAcknowledgmentV1,
			LocalSessionID:    clientSessionID,
			AcknowledgmentIDs: []proto.PacketID{reply.ID},
			RemoteSessionID:   reply.LocalSessionID,
		}
		acknowledgmentBytes, err := acknowledgmentPacket.Bytes()
		if err != nil {
			t.Fatalf("serialize probe acknowledgment: %v", err)
		}
		_, err = probeConnection.Write(acknowledgmentBytes)
		if err != nil {
			t.Fatalf("write probe acknowledgment %d: %v", probeIndex, err)
		}
		answered++
	}
	return answered
}

// P_ACK_V1 packets carrying a session id the server never issued are the cheapest
// pre-decrypt traffic an off-path source can produce; upstream discards each one
// without charging any connection budget.
func startUnauthenticatedCookieResponseFlood(t *testing.T, serverAddress string) func() {
	t.Helper()
	floodConnection, err := net.Dial("udp4", serverAddress)
	if err != nil {
		t.Fatalf("dial pre-authentication flood socket: %v", err)
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		defer floodConnection.Close()
		ticker := time.NewTicker(preAuthenticationJunkInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
			}
			var junkSessionID proto.SessionID
			var junkCookie proto.SessionID
			_, randomErr := rand.Read(junkSessionID[:])
			if randomErr != nil {
				return
			}
			_, randomErr = rand.Read(junkCookie[:])
			if randomErr != nil {
				return
			}
			junkPacket := &proto.Packet{
				Opcode:            proto.OpcodeAcknowledgmentV1,
				LocalSessionID:    junkSessionID,
				AcknowledgmentIDs: []proto.PacketID{0},
				RemoteSessionID:   junkCookie,
			}
			junkBytes, serializeErr := junkPacket.Bytes()
			if serializeErr != nil {
				return
			}
			_, writeErr := floodConnection.Write(junkBytes)
			if writeErr != nil {
				return
			}
		}
	}()
	return func() {
		close(done)
		<-stopped
	}
}
