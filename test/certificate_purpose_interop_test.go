package test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
)

// The upstream sample client certificate carries neither extendedKeyUsage,
// keyUsage nor Netscape Cert Type, so --ns-cert-type client resolves to
// OpenSSL X509_PURPOSE_SSL_CLIENT with nothing to reject it.
func TestOpenVPNInteropNSCertTypeAcceptsPeerCertificateWithoutExtendedKeyUsage(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	t.Run("real_server_accepts_repo_client", func(t *testing.T) {
		t.Parallel()
		runNSCertTypeRealServerAcceptsRepoClient(t, env)
	})
	t.Run("repo_server_accepts_real_client", func(t *testing.T) {
		t.Parallel()
		runNSCertTypeRepoServerAcceptsRealClient(t, env)
	})
}

func runNSCertTypeRealServerAcceptsRepoClient(t *testing.T, env interopEnvironment) {
	t.Helper()
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	serverPort := reserveInteropPort(t, "udp")
	clientPort := reserveInteropPort(t, "udp")
	renderInteropTemplate(t, "tls-server.conf.tmpl", filepath.Join(workspace.renderedDir, "server-tls.conf"), tlsServerTemplateData{
		Protocol:             "udp4",
		Port:                 serverPort,
		CAPath:               filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		CertPath:             filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		KeyPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		NSCertType:           "client",
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          strings.Join([]string{"AES-256-GCM", "AES-128-GCM"}, ":"),
		LogPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "server.log")),
	})
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-nscerttype-real-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "server-tls.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	serverLogPath := filepath.Join(workspace.logsDir, "server.log")
	waitForLogLine(t, serverLogPath, "Initialization Sequence Completed", 20*time.Second)

	clientContext, cancelClient := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelClient()
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context: clientContext,
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ClientTransportOptions{
			Remotes:     []openvpn.Remote{clientRemote(t, net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", serverPort)), "udp4")},
			DialContext: bindPortDialContextWithRecorder(clientPort, nil),
			Protocol:    "udp4",
		},
		DataChannel: openvpn.ClientDataChannelOptions{
			Ciphers: []string{"AES-256-GCM", "AES-128-GCM"},
		},
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Pull:         openvpn.ClientPullOptions{Enabled: true},
		KeyDirection: 1,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatalf("start client: %v", err)
	}
	configuration := waitForClientIfconfig(t, client, 20*time.Second)
	exchangeTLSClientEcho(t, client, configuration, 1, 0)
	assertLogContains(t, serverLogPath, []string{"VERIFY OK: nsCertType=CLIENT"})
}

func runNSCertTypeRepoServerAcceptsRealClient(t *testing.T, env interopEnvironment) {
	t.Helper()
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	listenPort := reserveInteropPort(t, "udp")
	serverContext, cancelServer := context.WithTimeout(context.Background(), 60*time.Second)
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
			Ciphers: []string{"AES-256-GCM", "AES-128-GCM"},
		},
		TLS: openvpn.ServerTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
			NSCertificateType:    "client",
		},
		Tunnel: openvpn.ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
			Topology:     "subnet",
		},
		KeyDirection: 0,
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatalf("start server: %v", err)
	}

	clientLogPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "client.log"))
	renderInteropTemplate(t, "tls-client.conf.tmpl", filepath.Join(workspace.renderedDir, "client-tls.conf"), tlsClientTemplateData{
		Protocol:             "udp4",
		RemoteHost:           "host.docker.internal",
		RemotePort:           listenPort,
		CAPath:               filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		CertPath:             filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.crt")),
		KeyPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.key")),
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          strings.Join([]string{"AES-256-GCM", "AES-128-GCM"}, ":"),
		LogPath:              clientLogPath,
	})
	clientContainer := startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:  "sing-openvpn-nscerttype-real-client-" + uniqueDockerName(t.Name()),
		Image: env.image,
		Command: []string{
			"bash",
			"-lc",
			"openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "client-tls.conf")) +
				" --daemon --writepid " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "client.pid")) +
				" && until grep -q 'Initialization Sequence Completed' " + clientLogPath + "; do sleep 0.1; done && ping -c 1 -W 3 10.8.0.1",
		},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})

	packetContext, cancelPacket := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelPacket()
	for {
		packet, readErr := server.ReadDataPacket(packetContext)
		if readErr != nil {
			t.Fatalf("read echo request from real OpenVPN client: %v", readErr)
		}
		reply, replyErr := buildStaticICMPEchoReply(packet.Payload)
		if replyErr != nil {
			continue
		}
		writeErr := server.WriteDataPacket(packet.PeerAddress, reply)
		if writeErr != nil {
			t.Fatalf("write echo reply to real OpenVPN client: %v", writeErr)
		}
		break
	}
	waitResult := clientContainer.Wait(t, 20*time.Second)
	if waitResult.ExitCode != 0 {
		t.Fatalf("real OpenVPN client failed: %s", waitResult.Logs)
	}
}
