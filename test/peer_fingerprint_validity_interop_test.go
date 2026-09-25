package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
)

const (
	peerFingerprintServerCertFileName = "peer-fingerprint-server.crt"
	peerFingerprintServerKeyFileName  = "peer-fingerprint-server.key"
	peerFingerprintClientCertFileName = "peer-fingerprint-client.crt"
	peerFingerprintClientKeyFileName  = "peer-fingerprint-client.key"
	peerFingerprintDataCiphers        = "AES-256-GCM:AES-128-GCM"
	peerFingerprintSequenceCompleted  = "Initialization Sequence Completed"
)

var peerFingerprintDataCipherList = []string{"AES-256-GCM", "AES-128-GCM"}

// A peer pinned by --peer-fingerprint without --ca keeps its tunnel even when
// its certificate is expired or not yet valid: upstream never loads a trust
// store for it, and verify_callback reports success for every chain
// verification error, the validity window included.
func TestOpenVPNInteropPeerFingerprintWithoutCAAcceptsPeerOutsideValidityWindow(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	t.Run("repo_client_accepts_expired_real_server", func(t *testing.T) {
		t.Parallel()
		runPeerFingerprintRepoClientAcceptsExpiredRealServer(t, env)
	})
	t.Run("repo_server_accepts_not_yet_valid_real_client", func(t *testing.T) {
		t.Parallel()
		runPeerFingerprintRepoServerAcceptsNotYetValidRealClient(t, env)
	})
}

func runPeerFingerprintRepoClientAcceptsExpiredRealServer(t *testing.T, env interopEnvironment) {
	t.Helper()
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	expiredServerCertificate, expiredServerKey := generateTestSelfSignedCertificate(t,
		"openvpn-peer-fingerprint-expired-server", x509.ExtKeyUsageServerAuth,
		time.Now().Add(-72*time.Hour), time.Now().Add(-24*time.Hour))
	clientCertificate, clientKey := generateTestSelfSignedCertificate(t,
		"openvpn-peer-fingerprint-client", x509.ExtKeyUsageClientAuth,
		time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	writeTestPEM(t, workspace.fixturesDir, peerFingerprintServerCertFileName, "CERTIFICATE", expiredServerCertificate.Raw)
	writeTestPKCS8Key(t, workspace.fixturesDir, peerFingerprintServerKeyFileName, expiredServerKey)
	writeTestPEM(t, workspace.fixturesDir, peerFingerprintClientCertFileName, "CERTIFICATE", clientCertificate.Raw)
	writeTestPKCS8Key(t, workspace.fixturesDir, peerFingerprintClientKeyFileName, clientKey)

	serverPort := reserveInteropPort(t, "udp")
	clientPort := reserveInteropPort(t, "udp")
	renderInteropTemplate(t, "tls-server.conf.tmpl", filepath.Join(workspace.renderedDir, "server-tls.conf"), tlsServerTemplateData{
		Protocol:             "udp4",
		Port:                 serverPort,
		CertPath:             peerFingerprintFixturePath(peerFingerprintServerCertFileName),
		KeyPath:              peerFingerprintFixturePath(peerFingerprintServerKeyFileName),
		PeerFingerprints:     []string{upstreamPeerFingerprint(clientCertificate)},
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          peerFingerprintDataCiphers,
		LogPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "server.log")),
	})
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-peer-fingerprint-real-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "server-tls.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	serverLogPath := filepath.Join(workspace.logsDir, "server.log")
	waitForLogLine(t, serverLogPath, peerFingerprintSequenceCompleted, 20*time.Second)
	assertLogContains(t, serverLogPath, []string{"WARNING: Your certificate has expired!"})

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
			Ciphers: peerFingerprintDataCipherList,
		},
		TLS: openvpn.ClientTLSOptions{
			Certificate:     openvpn.Material{Path: filepath.Join(workspace.fixturesDir, peerFingerprintClientCertFileName)},
			Key:             openvpn.Material{Path: filepath.Join(workspace.fixturesDir, peerFingerprintClientKeyFileName)},
			PeerFingerprint: []string{repositoryPeerFingerprint(expiredServerCertificate)},
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

func runPeerFingerprintRepoServerAcceptsNotYetValidRealClient(t *testing.T, env interopEnvironment) {
	t.Helper()
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	serverCertificate, serverKey := generateTestSelfSignedCertificate(t,
		"openvpn-peer-fingerprint-server", x509.ExtKeyUsageServerAuth,
		time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	notYetValidClientCertificate, notYetValidClientKey := generateTestSelfSignedCertificate(t,
		"openvpn-peer-fingerprint-not-yet-valid-client", x509.ExtKeyUsageClientAuth,
		time.Now().Add(24*time.Hour), time.Now().Add(72*time.Hour))
	writeTestPEM(t, workspace.fixturesDir, peerFingerprintServerCertFileName, "CERTIFICATE", serverCertificate.Raw)
	writeTestPKCS8Key(t, workspace.fixturesDir, peerFingerprintServerKeyFileName, serverKey)
	writeTestPEM(t, workspace.fixturesDir, peerFingerprintClientCertFileName, "CERTIFICATE", notYetValidClientCertificate.Raw)
	writeTestPKCS8Key(t, workspace.fixturesDir, peerFingerprintClientKeyFileName, notYetValidClientKey)

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
			Ciphers: peerFingerprintDataCipherList,
		},
		TLS: openvpn.ServerTLSOptions{
			Certificate:     openvpn.Material{Path: filepath.Join(workspace.fixturesDir, peerFingerprintServerCertFileName)},
			Key:             openvpn.Material{Path: filepath.Join(workspace.fixturesDir, peerFingerprintServerKeyFileName)},
			PeerFingerprint: []string{repositoryPeerFingerprint(notYetValidClientCertificate)},
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
		CertPath:             peerFingerprintFixturePath(peerFingerprintClientCertFileName),
		KeyPath:              peerFingerprintFixturePath(peerFingerprintClientKeyFileName),
		PeerFingerprints:     []string{upstreamPeerFingerprint(serverCertificate)},
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          peerFingerprintDataCiphers,
		LogPath:              clientLogPath,
	})
	clientContainer := startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:  "sing-openvpn-peer-fingerprint-real-client-" + uniqueDockerName(t.Name()),
		Image: env.image,
		Command: []string{
			"bash",
			"-lc",
			"openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "client-tls.conf")) +
				" --daemon --writepid " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "client.pid")) +
				" && until grep -q '" + peerFingerprintSequenceCompleted + "' " + clientLogPath + "; do sleep 0.1; done && ping -c 1 -W 3 10.8.0.1",
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
	assertLogContains(t, filepath.Join(workspace.logsDir, "client.log"), []string{"WARNING: Your certificate is not yet valid!"})
}

func peerFingerprintFixturePath(fileName string) string {
	return filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", fileName))
}

func generateTestSelfSignedCertificate(
	t *testing.T,
	commonName string,
	extendedKeyUsage x509.ExtKeyUsage,
	notBefore time.Time,
	notAfter time.Time,
) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{extendedKeyUsage},
		BasicConstraintsValid: true,
	}
	certificateBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedCertificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		t.Fatal(err)
	}
	return parsedCertificate, privateKey
}

// Upstream parse_hash_fingerprint reads the colon separated hexadecimal digest
// that OpenSSL prints for --peer-fingerprint.
func upstreamPeerFingerprint(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.Raw)
	octets := make([]string, 0, len(digest))
	for _, octet := range digest {
		octets = append(octets, fmt.Sprintf("%02X", octet))
	}
	return strings.Join(octets, ":")
}

func repositoryPeerFingerprint(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(digest[:])
}
