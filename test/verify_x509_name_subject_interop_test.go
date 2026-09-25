package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
)

const (
	verifyX509NameAuthorityFileName  = "verify-x509-name-ca.crt"
	verifyX509NameServerCertFileName = "verify-x509-name-server.crt"
	verifyX509NameServerKeyFileName  = "verify-x509-name-server.key"
	verifyX509NameClientCertFileName = "verify-x509-name-client.crt"
	verifyX509NameClientKeyFileName  = "verify-x509-name-client.key"
	verifyX509NameDataCiphers        = "AES-256-GCM:AES-128-GCM"
	verifyX509NameSequenceCompleted  = "Initialization Sequence Completed"

	verifyX509NameServerSubject = "C=US, O=Interop-Org + OU=Interop-Uni, serialNumber=4711, " +
		"CN=openvpn-verify-x509-name-server, name=x509-name-subject, " +
		"emailAddress=server@example.invalid"
	verifyX509NameClientSubject = "C=US, O=Interop-Org + OU=Interop-Uni, serialNumber=4712, " +
		"CN=openvpn-verify-x509-name-client, name=x509-name-subject, " +
		"emailAddress=client@example.invalid"
)

var verifyX509NameDataCipherList = []string{"AES-256-GCM", "AES-128-GCM"}

// --verify-x509-name subject compares against the whole encoded distinguished
// name that upstream x509_get_subject prints: every attribute type in encoding
// order including the ones crypto/x509 does not model, and the members of a
// multi-valued relative name joined with " + " rather than ", ".
func TestOpenVPNInteropVerifyX509NameSubjectRendersTheEncodedDistinguishedName(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	t.Run("repo_client_verifies_real_server", func(t *testing.T) {
		t.Parallel()
		runVerifyX509NameRepoClientVerifiesRealServer(t, env)
	})
	t.Run("repo_server_verifies_real_client", func(t *testing.T) {
		t.Parallel()
		runVerifyX509NameRepoServerVerifiesRealClient(t, env)
	})
}

func runVerifyX509NameRepoClientVerifiesRealServer(t *testing.T, env interopEnvironment) {
	t.Helper()
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	writeVerifyX509NameMaterial(t, workspace)

	serverPort := reserveInteropPort(t, "udp")
	clientPort := reserveInteropPort(t, "udp")
	renderInteropTemplate(t, "tls-server.conf.tmpl", filepath.Join(workspace.renderedDir, "server-tls.conf"), tlsServerTemplateData{
		Protocol:             "udp4",
		Port:                 serverPort,
		CAPath:               verifyX509NameFixturePath(verifyX509NameAuthorityFileName),
		CertPath:             verifyX509NameFixturePath(verifyX509NameServerCertFileName),
		KeyPath:              verifyX509NameFixturePath(verifyX509NameServerKeyFileName),
		VerifyX509Name:       verifyX509NameClientSubject,
		VerifyX509Type:       "subject",
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          verifyX509NameDataCiphers,
		LogPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "server.log")),
	})
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-verify-x509-name-real-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "server-tls.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	serverLogPath := filepath.Join(workspace.logsDir, "server.log")
	waitForLogLine(t, serverLogPath, verifyX509NameSequenceCompleted, 20*time.Second)

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
			Ciphers: verifyX509NameDataCipherList,
		},
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join(workspace.fixturesDir, verifyX509NameAuthorityFileName)},
			Certificate:          openvpn.Material{Path: filepath.Join(workspace.fixturesDir, verifyX509NameClientCertFileName)},
			Key:                  openvpn.Material{Path: filepath.Join(workspace.fixturesDir, verifyX509NameClientKeyFileName)},
			VerifyX509Name:       verifyX509NameServerSubject,
			VerifyX509Type:       "subject",
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
	assertLogContains(t, serverLogPath, []string{"VERIFY X509NAME OK: " + verifyX509NameClientSubject})
}

func runVerifyX509NameRepoServerVerifiesRealClient(t *testing.T, env interopEnvironment) {
	t.Helper()
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	writeVerifyX509NameMaterial(t, workspace)

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
			Ciphers: verifyX509NameDataCipherList,
		},
		TLS: openvpn.ServerTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join(workspace.fixturesDir, verifyX509NameAuthorityFileName)},
			Certificate:          openvpn.Material{Path: filepath.Join(workspace.fixturesDir, verifyX509NameServerCertFileName)},
			Key:                  openvpn.Material{Path: filepath.Join(workspace.fixturesDir, verifyX509NameServerKeyFileName)},
			VerifyX509Name:       verifyX509NameClientSubject,
			VerifyX509Type:       "subject",
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
		CAPath:               verifyX509NameFixturePath(verifyX509NameAuthorityFileName),
		CertPath:             verifyX509NameFixturePath(verifyX509NameClientCertFileName),
		KeyPath:              verifyX509NameFixturePath(verifyX509NameClientKeyFileName),
		VerifyX509Name:       verifyX509NameServerSubject,
		VerifyX509Type:       "subject",
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          verifyX509NameDataCiphers,
		LogPath:              clientLogPath,
	})
	clientContainer := startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:  "sing-openvpn-verify-x509-name-real-client-" + uniqueDockerName(t.Name()),
		Image: env.image,
		Command: []string{
			"bash",
			"-lc",
			"openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "client-tls.conf")) +
				" --daemon --writepid " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "client.pid")) +
				" && until grep -q '" + verifyX509NameSequenceCompleted + "' " + clientLogPath + "; do sleep 0.1; done && ping -c 1 -W 3 10.8.0.1",
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
	assertLogContains(t, filepath.Join(workspace.logsDir, "client.log"), []string{"VERIFY X509NAME OK: " + verifyX509NameServerSubject})
}

func verifyX509NameFixturePath(fileName string) string {
	return filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", fileName))
}

func writeVerifyX509NameMaterial(t *testing.T, workspace interopWorkspace) {
	t.Helper()
	authorityKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorityTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "openvpn-verify-x509-name-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	authorityDER, err := x509.CreateCertificate(rand.Reader, authorityTemplate, authorityTemplate, &authorityKey.PublicKey, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	authorityCertificate, err := x509.ParseCertificate(authorityDER)
	if err != nil {
		t.Fatal(err)
	}
	writeTestPEM(t, workspace.fixturesDir, verifyX509NameAuthorityFileName, "CERTIFICATE", authorityDER)

	serverDER, serverKey := issueVerifyX509NameCertificate(t, authorityCertificate, authorityKey, 2,
		encodeVerifyX509NameSubject(t, "4711", "openvpn-verify-x509-name-server", "server@example.invalid"),
		x509.ExtKeyUsageServerAuth)
	writeTestPEM(t, workspace.fixturesDir, verifyX509NameServerCertFileName, "CERTIFICATE", serverDER)
	writeTestPKCS8Key(t, workspace.fixturesDir, verifyX509NameServerKeyFileName, serverKey)

	clientDER, clientKey := issueVerifyX509NameCertificate(t, authorityCertificate, authorityKey, 3,
		encodeVerifyX509NameSubject(t, "4712", "openvpn-verify-x509-name-client", "client@example.invalid"),
		x509.ExtKeyUsageClientAuth)
	writeTestPEM(t, workspace.fixturesDir, verifyX509NameClientCertFileName, "CERTIFICATE", clientDER)
	writeTestPKCS8Key(t, workspace.fixturesDir, verifyX509NameClientKeyFileName, clientKey)
}

func issueVerifyX509NameCertificate(
	t *testing.T,
	authorityCertificate *x509.Certificate,
	authorityKey *ecdsa.PrivateKey,
	serialNumber int64,
	rawSubject []byte,
	extendedKeyUsage x509.ExtKeyUsage,
) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serialNumber),
		RawSubject:            rawSubject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{extendedKeyUsage},
		BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, authorityCertificate, &privateKey.PublicKey, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	return certificateDER, privateKey
}

// The organization and organizational unit share one relative name, the serial
// number precedes the common name, and the trailing name and emailAddress
// attributes are types pkix.Name drops on the way back out.
func encodeVerifyX509NameSubject(t *testing.T, serialNumber string, commonName string, emailAddress string) []byte {
	t.Helper()
	rawSubject, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"}},
		{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Interop-Org"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Interop-Uni"},
		},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 5}, Value: serialNumber}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: commonName}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 41}, Value: "x509-name-subject"}},
		{{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: emailAddress}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return rawSubject
}
