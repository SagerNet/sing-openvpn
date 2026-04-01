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
)

func TestOpenVPNInteropPullFalseP2PData(t *testing.T) {
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	serverPort := reserveUDPPort(t)
	serverConfiguration := fmt.Sprintf(`port %d
proto udp4
dev tun
ifconfig 10.44.0.1 10.44.0.2
tls-server
ca %s
cert %s
key %s
dh none
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
persist-key
persist-tun
verb 4
log %s
`, serverPort,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "p2p-server.log")),
	)
	serverConfigurationPath := filepath.Join(workspace.renderedDir, "p2p-server.conf")
	err := os.WriteFile(serverConfigurationPath, []byte(serverConfiguration), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-p2p-server-" + sanitizeDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"openvpn", "--config", filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "p2p-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	serverLogPath := filepath.Join(workspace.logsDir, "p2p-server.log")
	waitForAnyLogLine(t, serverLogPath, []string{"UDPv4 link remote", "Initialization Sequence Completed"}, 15*time.Second)

	clientContext, cancelClient := context.WithTimeout(context.Background(), 20*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context:   clientContext,
		Mode:      openvpn.ModeTLS,
		Transport: clientTransportOptions(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), "udp4"),
		DataChannel: openvpn.ClientDataChannelOptions{
			Cipher:  "AES-256-GCM",
			Ciphers: []string{"AES-256-GCM"},
			Auth:    "SHA256",
		},
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Pull:   openvpn.ClientPullOptions{Enabled: false},
		Tunnel: openvpn.ClientTunnelOptions{LocalAddress: []netip.Prefix{netip.MustParsePrefix("10.44.0.2/32")}},
		Timing: openvpn.ClientTimingOptions{HandWindow: 10 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancelClient()
		_ = client.Close()
	})
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	waitForClientReady(t, client, 10*time.Second)
	waitForLogLine(t, serverLogPath, "Initialization Sequence Completed", 10*time.Second)

	request := buildStaticICMPEchoRequest(t,
		netip.MustParseAddr("10.44.0.2"),
		netip.MustParseAddr("10.44.0.1"),
		0x4410,
		1,
		[]byte("pull-false-p2p-data"),
	)
	writeClientDataPacket(t, client, request, 10*time.Second)
	replyContext, cancelReply := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelReply()
	var reply []byte
	for {
		reply, err = client.ReadDataPacket(replyContext)
		if err != nil {
			t.Fatal(err)
		}
		if len(reply) > 0 && reply[0]>>4 == 4 {
			break
		}
	}
	assertStaticICMPEchoReply(t, request, reply)
}

func TestOpenVPNInteropLZOCompressedRequest(t *testing.T) {
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	serverPort := reserveUDPPort(t)
	serverConfiguration := fmt.Sprintf(`port %d
proto udp4
dev tun
topology subnet
server 10.45.0.0 255.255.255.0
ca %s
cert %s
key %s
dh none
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
comp-lzo yes
allow-compression yes
persist-key
persist-tun
verb 7
log %s
`, serverPort,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "lzo-server.log")),
	)
	serverConfigurationPath := filepath.Join(workspace.renderedDir, "lzo-server.conf")
	err := os.WriteFile(serverConfigurationPath, []byte(serverConfiguration), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-lzo-server-" + sanitizeDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"openvpn", "--config", filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "lzo-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	serverLogPath := filepath.Join(workspace.logsDir, "lzo-server.log")
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
			CompressionLZO:   "yes",
			AllowCompression: "yes",
		},
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Pull: openvpn.ClientPullOptions{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancelClient()
		_ = client.Close()
	})
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	configuration := waitForClientIfconfig(t, client, 10*time.Second)
	request := buildStaticICMPEchoRequest(t,
		configuration.LocalIPv4[0].Addr(),
		netip.MustParseAddr("10.45.0.1"),
		0x4510,
		1,
		bytes.Repeat([]byte("sing-openvpn-lzo-"), 64),
	)
	packetLengthRecorder.Begin()
	writeClientDataPacket(t, client, request, 10*time.Second)
	replyContext, cancelReply := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelReply()
	for {
		reply, readErr := client.ReadDataPacket(replyContext)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if validateStaticICMPEchoReply(request, reply) == nil {
			break
		}
	}
	readPacketLengths, writePacketLengths := packetLengthRecorder.End()
	assertCompressedUDPPackets(t, readPacketLengths, len(request))
	assertCompressedUDPPackets(t, writePacketLengths, len(request))
}
