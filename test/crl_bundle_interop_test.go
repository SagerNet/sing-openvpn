package test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
)

const (
	crlBundleCAFileName             = "crl-bundle-ca.crt"
	crlBundleRevocationFileName     = "crl-bundle.pem"
	crlBundleServerCertFileName     = "crl-bundle-server.crt"
	crlBundleServerKeyFileName      = "crl-bundle-server.key"
	crlBundleClientCertFileName     = "crl-bundle-client.crt"
	crlBundleClientKeyFileName      = "crl-bundle-client.key"
	crlBundleRevokedCertFileName    = "crl-bundle-revoked-client.crt"
	crlBundleRevokedKeyFileName     = "crl-bundle-revoked-client.key"
	crlBundleDataCiphers            = "AES-256-GCM:AES-128-GCM"
	crlBundleUpstreamLoadedTwoCRLs  = "CRL: loaded 2 CRLs"
	crlBundleInitializationComplete = "Initialization Sequence Completed"
)

var crlBundleDataCipherList = []string{"AES-256-GCM", "AES-128-GCM"}

// A --crl-verify file holds one CRL per issuing CA. Every peer is signed by the
// second CA, so the CRL that covers it is the second PEM block of the bundle
// and the first block's issuer never appears in the peer's chain.
func TestOpenVPNInteropCRLBundleAppliesEveryEntryPerIssuer(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	t.Run("repo_client_accepts_real_server_covered_by_later_bundle_entry", func(t *testing.T) {
		t.Parallel()
		runCRLBundleRepoClientAcceptsRealServer(t, env)
	})
	t.Run("repo_server_accepts_real_client_covered_by_later_bundle_entry", func(t *testing.T) {
		t.Parallel()
		runCRLBundleRepoServerAcceptsRealClient(t, env)
	})
	t.Run("repo_server_rejects_real_client_revoked_by_later_bundle_entry", func(t *testing.T) {
		t.Parallel()
		runCRLBundleRepoServerRejectsRevokedRealClient(t, env)
	})
}

func writeCRLBundleInteropPKI(t *testing.T, workspace interopWorkspace) {
	t.Helper()
	firstAuthority, firstAuthorityKey := generateTestRootCA(t, "openvpn-crl-bundle-first-ca")
	secondAuthority, secondAuthorityKey := generateTestRootCA(t, "openvpn-crl-bundle-second-ca")
	serverCertificate, serverKey := generateTestSignedCertificate(
		t, "openvpn-crl-bundle-server", secondAuthority, secondAuthorityKey, x509.ExtKeyUsageServerAuth)
	clientCertificate, clientKey := generateTestSignedCertificate(
		t, "openvpn-crl-bundle-client", secondAuthority, secondAuthorityKey, x509.ExtKeyUsageClientAuth)
	revokedCertificate, revokedKey := generateTestSignedCertificate(
		t, "openvpn-crl-bundle-revoked-client", secondAuthority, secondAuthorityKey, x509.ExtKeyUsageClientAuth)
	writeTestPEM(t, workspace.fixturesDir, crlBundleServerCertFileName, "CERTIFICATE", serverCertificate.Raw)
	writeTestPKCS8Key(t, workspace.fixturesDir, crlBundleServerKeyFileName, serverKey)
	writeTestPEM(t, workspace.fixturesDir, crlBundleClientCertFileName, "CERTIFICATE", clientCertificate.Raw)
	writeTestPKCS8Key(t, workspace.fixturesDir, crlBundleClientKeyFileName, clientKey)
	writeTestPEM(t, workspace.fixturesDir, crlBundleRevokedCertFileName, "CERTIFICATE", revokedCertificate.Raw)
	writeTestPKCS8Key(t, workspace.fixturesDir, crlBundleRevokedKeyFileName, revokedKey)
	writeTestPEMBundle(t, filepath.Join(workspace.fixturesDir, crlBundleCAFileName),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: firstAuthority.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: secondAuthority.Raw}),
	)
	thisUpdate := time.Now().Add(-time.Minute)
	nextUpdate := time.Now().Add(24 * time.Hour)
	writeTestPEMBundle(t, filepath.Join(workspace.fixturesDir, crlBundleRevocationFileName),
		encodeTestCRLSigned(t, firstAuthority, firstAuthorityKey, nil, thisUpdate, nextUpdate),
		encodeTestCRLSigned(t, secondAuthority, secondAuthorityKey, []*x509.Certificate{revokedCertificate}, thisUpdate, nextUpdate),
	)
}

func crlBundleFixturePath(fileName string) string {
	return filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", fileName))
}

func runCRLBundleRepoClientAcceptsRealServer(t *testing.T, env interopEnvironment) {
	t.Helper()
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	writeCRLBundleInteropPKI(t, workspace)

	serverPort := reserveInteropPort(t, "udp")
	clientPort := reserveInteropPort(t, "udp")
	renderInteropTemplate(t, "tls-server.conf.tmpl", filepath.Join(workspace.renderedDir, "server-tls.conf"), tlsServerTemplateData{
		Protocol:             "udp4",
		Port:                 serverPort,
		CAPath:               crlBundleFixturePath(crlBundleCAFileName),
		CertPath:             crlBundleFixturePath(crlBundleServerCertFileName),
		KeyPath:              crlBundleFixturePath(crlBundleServerKeyFileName),
		CRLVerifyPath:        crlBundleFixturePath(crlBundleRevocationFileName),
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          crlBundleDataCiphers,
		LogPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "server.log")),
	})
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-crl-bundle-real-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "server-tls.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	serverLogPath := filepath.Join(workspace.logsDir, "server.log")
	waitForLogLine(t, serverLogPath, crlBundleInitializationComplete, 20*time.Second)
	assertLogContains(t, serverLogPath, []string{crlBundleUpstreamLoadedTwoCRLs})

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
			Ciphers: crlBundleDataCipherList,
		},
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join(workspace.fixturesDir, crlBundleCAFileName)},
			Certificate:          openvpn.Material{Path: filepath.Join(workspace.fixturesDir, crlBundleClientCertFileName)},
			Key:                  openvpn.Material{Path: filepath.Join(workspace.fixturesDir, crlBundleClientKeyFileName)},
			CRLVerify:            filepath.Join(workspace.fixturesDir, crlBundleRevocationFileName),
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
}

func runCRLBundleRepoServerAcceptsRealClient(t *testing.T, env interopEnvironment) {
	t.Helper()
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	writeCRLBundleInteropPKI(t, workspace)

	server, listenPort := startCRLBundleRepoServer(t, workspace)
	defer server.Close()

	clientLogPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "client.log"))
	renderCRLBundleRealClientConfiguration(t, workspace, listenPort, crlBundleClientCertFileName, crlBundleClientKeyFileName, clientLogPath)
	clientContainer := startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:  "sing-openvpn-crl-bundle-real-client-" + uniqueDockerName(t.Name()),
		Image: env.image,
		Command: []string{
			"bash",
			"-lc",
			"openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "client-tls.conf")) +
				" --daemon --writepid " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "client.pid")) +
				" && until grep -q '" + crlBundleInitializationComplete + "' " + clientLogPath + "; do sleep 0.1; done && ping -c 1 -W 3 10.8.0.1",
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
	assertLogContains(t, filepath.Join(workspace.logsDir, "client.log"), []string{crlBundleUpstreamLoadedTwoCRLs})
}

func runCRLBundleRepoServerRejectsRevokedRealClient(t *testing.T, env interopEnvironment) {
	t.Helper()
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	writeCRLBundleInteropPKI(t, workspace)

	server, listenPort := startCRLBundleRepoServer(t, workspace)
	defer server.Close()

	clientLogPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "revoked-client.log"))
	renderCRLBundleRealClientConfiguration(t, workspace, listenPort, crlBundleRevokedCertFileName, crlBundleRevokedKeyFileName, clientLogPath)
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:       "sing-openvpn-crl-bundle-revoked-client-" + uniqueDockerName(t.Name()),
		Image:      env.image,
		Command:    []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "client-tls.conf"))},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})
	localClientLogPath := filepath.Join(workspace.logsDir, "revoked-client.log")
	waitForAnyLogLine(t, localClientLogPath, []string{
		"Received fatal SSL alert: bad certificate",
		"TLS Error: TLS handshake failed",
	}, 40*time.Second)
	assertLogDoesNotContain(t, localClientLogPath, crlBundleInitializationComplete)
}

func startCRLBundleRepoServer(t *testing.T, workspace interopWorkspace) (*openvpn.Server, int) {
	t.Helper()
	listenPort := reserveInteropPort(t, "udp")
	serverContext, cancelServer := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancelServer)
	server, err := openvpn.NewServer(openvpn.ServerOptions{
		NewOutboundQueue: newTestOutboundQueue,
		Context:          serverContext,
		Mode:             openvpn.ModeTLS,
		Transport: openvpn.ServerTransportOptions{
			ListenAddress: fmt.Sprintf("0.0.0.0:%d", listenPort),
			Protocol:      "udp4",
		},
		DataChannel: openvpn.ServerDataChannelOptions{
			Ciphers: crlBundleDataCipherList,
		},
		TLS: openvpn.ServerTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join(workspace.fixturesDir, crlBundleCAFileName)},
			Certificate:          openvpn.Material{Path: filepath.Join(workspace.fixturesDir, crlBundleServerCertFileName)},
			Key:                  openvpn.Material{Path: filepath.Join(workspace.fixturesDir, crlBundleServerKeyFileName)},
			CRLVerify:            filepath.Join(workspace.fixturesDir, crlBundleRevocationFileName),
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
	err = server.Start()
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	return server, listenPort
}

func renderCRLBundleRealClientConfiguration(
	t *testing.T,
	workspace interopWorkspace,
	listenPort int,
	certificateFileName string,
	keyFileName string,
	clientLogPath string,
) {
	t.Helper()
	renderInteropTemplate(t, "tls-client.conf.tmpl", filepath.Join(workspace.renderedDir, "client-tls.conf"), tlsClientTemplateData{
		Protocol:             "udp4",
		RemoteHost:           "host.docker.internal",
		RemotePort:           listenPort,
		CAPath:               crlBundleFixturePath(crlBundleCAFileName),
		CertPath:             crlBundleFixturePath(certificateFileName),
		KeyPath:              crlBundleFixturePath(keyFileName),
		CRLVerifyPath:        crlBundleFixturePath(crlBundleRevocationFileName),
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          crlBundleDataCiphers,
		LogPath:              clientLogPath,
	})
}

func assertLogDoesNotContain(t *testing.T, logPath string, value string) {
	t.Helper()
	logContent, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log %s: %v", logPath, err)
	}
	if strings.Contains(string(logContent), value) {
		t.Fatalf("unexpected %q in %s\n%s", value, logPath, string(logContent))
	}
}
