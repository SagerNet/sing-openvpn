package test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	E "github.com/sagernet/sing/common/exceptions"
)

type compressionNegotiationInteropCase struct {
	name                            string
	serverCompressionDirectives     string
	allowCompression                string
	expectRejection                 bool
	expectServerToClientCompression bool
	expectClientToServerCompression bool
}

func TestOpenVPNInteropCompressionNegotiation(t *testing.T) {
	testCases := []compressionNegotiationInteropCase{
		{
			name: "pushed_lzo_stub_under_no",
			serverCompressionDirectives: `allow-compression no
comp-lzo no
push "comp-lzo no"`,
			allowCompression: "no",
		},
		{
			name: "pushed_stub_under_no",
			serverCompressionDirectives: `allow-compression no
compress stub
push "compress stub"`,
			allowCompression: "no",
		},
		{
			name: "pushed_stub_v2_under_no",
			serverCompressionDirectives: `allow-compression no
compress stub-v2
push "compress stub-v2"`,
			allowCompression: "no",
		},
		{
			name: "pushed_lzo_under_no",
			serverCompressionDirectives: `allow-compression yes
comp-lzo yes
push "comp-lzo yes"`,
			allowCompression: "no",
			expectRejection:  true,
		},
		{
			name: "pushed_lzo_under_asym",
			serverCompressionDirectives: `allow-compression yes
comp-lzo yes
push "comp-lzo yes"`,
			allowCompression:                "asym",
			expectServerToClientCompression: true,
		},
		{
			name: "pushed_lzo_under_yes",
			serverCompressionDirectives: `allow-compression yes
comp-lzo yes
push "comp-lzo yes"`,
			allowCompression:                "yes",
			expectServerToClientCompression: true,
			expectClientToServerCompression: true,
		},
		{
			name: "pushed_lz4_under_asym",
			serverCompressionDirectives: `allow-compression yes
compress lz4
push "compress lz4"`,
			allowCompression:                "asym",
			expectServerToClientCompression: true,
		},
		{
			name: "pushed_lz4_v2_under_asym",
			serverCompressionDirectives: `allow-compression yes
compress lz4-v2
push "compress lz4-v2"`,
			allowCompression:                "asym",
			expectServerToClientCompression: true,
		},
	}
	for _, version := range []string{"2.5.11", "2.6.14"} {
		t.Run("openvpn_"+version, func(versionTest *testing.T) {
			env := requireInteropEnvironmentVersion(versionTest, version)
			for _, testCase := range testCases {
				versionTest.Run(testCase.name, func(caseTest *testing.T) {
					runCompressionNegotiationInteropCase(caseTest, env, testCase)
				})
			}
		})
	}
}

func runCompressionNegotiationInteropCase(t *testing.T, env interopEnvironment, testCase compressionNegotiationInteropCase) {
	t.Helper()
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	serverPort := reserveUDPPort(t)
	serverConfiguration := fmt.Sprintf(`port %d
proto udp4
dev tun
topology subnet
server 10.46.0.0 255.255.255.0
ca %s
cert %s
key %s
dh none
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
%s
persist-key
persist-tun
verb 7
log %s
`, serverPort,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		testCase.serverCompressionDirectives,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "compression-server.log")),
	)
	serverConfigurationPath := filepath.Join(workspace.renderedDir, "compression-server.conf")
	err := os.WriteFile(serverConfigurationPath, []byte(serverConfiguration), 0o644)
	if err != nil {
		t.Fatalf("write compression server config: %v", err)
	}
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-compression-server-" + sanitizeDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"openvpn", "--config", filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "compression-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	serverLogPath := filepath.Join(workspace.logsDir, "compression-server.log")
	waitForLogLine(t, serverLogPath, "Initialization Sequence Completed", 20*time.Second)

	clientPort := reserveUDPPort(t)
	packetLengthRecorder := new(interopPacketLengthRecorder)
	clientContext, cancelClient := context.WithTimeout(context.Background(), 30*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context: clientContext,
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ClientTransportOptions{
			Remotes:     []openvpn.Remote{clientRemote(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), "udp4")},
			DialContext: bindPortDialContextWithRecorder(clientPort, packetLengthRecorder),
			Protocol:    "udp4",
		},
		DataChannel: openvpn.ClientDataChannelOptions{
			Cipher:           "AES-256-GCM",
			Ciphers:          []string{"AES-256-GCM"},
			Auth:             "SHA256",
			AllowCompression: testCase.allowCompression,
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
		t.Fatalf("create compression interop client: %v", err)
	}
	t.Cleanup(func() {
		cancelClient()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close compression interop client: %v", closeErr)
		}
	})
	err = client.Start()
	if err != nil {
		if testCase.expectRejection && E.IsMulti(err, openvpn.ErrCompressionPushRejected) {
			return
		}
		t.Fatalf("start compression interop client: %v", err)
	}
	if testCase.expectRejection {
		waitForClientTerminalError(t, client, 10*time.Second, openvpn.ErrCompressionPushRejected)
		return
	}

	configuration := waitForClientIfconfig(t, client, 10*time.Second)
	request := buildStaticICMPEchoRequest(t,
		configuration.LocalIPv4[0].Addr(),
		netip.MustParseAddr("10.46.0.1"),
		0x4610,
		1,
		bytes.Repeat([]byte{0x5a}, 1152),
	)
	packetLengthRecorder.Begin()
	writeClientDataPacket(t, client, request, 10*time.Second)
	replyContext, cancelReply := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelReply()
	for {
		reply, readErr := client.ReadDataPacket(replyContext)
		if readErr != nil {
			t.Fatalf("read compression interop reply: %v", readErr)
		}
		if validateStaticICMPEchoReply(request, reply) == nil {
			break
		}
	}
	serverToClientPacketLengths, clientToServerPacketLengths := packetLengthRecorder.End()
	assertCompressionNegotiationPacketLengths(t, "server to library", serverToClientPacketLengths, len(request), testCase.expectServerToClientCompression)
	assertCompressionNegotiationPacketLengths(t, "library to server", clientToServerPacketLengths, len(request), testCase.expectClientToServerCompression)
}

func assertCompressionNegotiationPacketLengths(t *testing.T, direction string, packetLengths []int, uncompressedPacketLength int, expectCompression bool) {
	t.Helper()
	if len(packetLengths) == 0 {
		t.Fatalf("recorded no %s UDP packets", direction)
	}
	if expectCompression {
		for _, packetLength := range packetLengths {
			if packetLength >= uncompressedPacketLength/2 {
				t.Fatalf("expected compressed %s UDP packets below %d bytes, got %v", direction, uncompressedPacketLength/2, packetLengths)
			}
		}
		return
	}
	for _, packetLength := range packetLengths {
		if packetLength >= uncompressedPacketLength {
			return
		}
	}
	t.Fatalf("expected an uncompressed %s UDP packet of at least %d bytes, got %v", direction, uncompressedPacketLength, packetLengths)
}
