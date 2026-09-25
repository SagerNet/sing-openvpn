package test

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
)

// multi.c matches a peer source address against the addresses
// multi_client_connect_late_setup() learned from --ifconfig-pool; a --tls-server
// that hands out no address keeps no such table and writes every decrypted
// payload to the tun device.
func TestOpenVPNInteropServerWithoutAddressPoolForwardsPeerTraffic(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	listenPort := reserveInteropPort(t, "udp")
	serverContext, cancelServer := context.WithTimeout(context.Background(), 90*time.Second)
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
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}

	peerAddress := netip.MustParseAddr("10.44.0.2")
	tunnelAddress := netip.MustParseAddr("10.44.0.1")
	dockerLogPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "nopool-client.log"))
	dockerConfigurationPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "nopool-client.conf"))
	clientConfiguration := fmt.Sprintf(`proto udp4
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
`, listenPort,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.key")),
		peerAddress,
		tunnelAddress,
		dockerLogPath,
	)
	err = os.WriteFile(filepath.Join(workspace.renderedDir, "nopool-client.conf"), []byte(clientConfiguration), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	clientContainer := startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:  "sing-openvpn-nopool-client-" + uniqueDockerName(t.Name()),
		Image: env.image,
		Command: []string{
			"bash",
			"-lc",
			"openvpn --config " + dockerConfigurationPath +
				" --daemon --writepid " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "client.pid")) +
				" && until grep -q 'Outgoing Data Channel: Cipher' " + dockerLogPath + "; do sleep 0.1; done" +
				" && ping -c 3 -W 10 " + tunnelAddress.String(),
		},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})

	packetContext, cancelPacket := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancelPacket()
	for {
		packet, readErr := server.ReadDataPacket(packetContext)
		if readErr != nil {
			t.Fatalf("read tunnel packet from unnumbered peer: %v", readErr)
		}
		reply, replyErr := buildStaticICMPEchoReply(packet.Payload)
		if replyErr != nil {
			continue
		}
		source := netip.AddrFrom4([4]byte(packet.Payload[12:16]))
		if source != peerAddress {
			t.Fatalf("expected tunnel packet from %s, got %s", peerAddress, source)
		}
		writeErr := server.WriteDataPacket(packet.PeerAddress, reply)
		if writeErr != nil {
			t.Fatalf("write tunnel packet to unnumbered peer: %v", writeErr)
		}
		break
	}
	waitResult := clientContainer.Wait(t, 40*time.Second)
	if waitResult.ExitCode != 0 {
		t.Fatalf("real OpenVPN peer failed: %s", waitResult.Logs)
	}
}
