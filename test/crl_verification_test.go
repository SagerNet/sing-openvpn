package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/sagernet/sing-openvpn"
)

type crlHandshakeMaterial struct {
	certificateAuthority Material
	serverCertificate    Material
	serverKey            Material
	clientCertificate    Material
	clientKey            Material
	caCertificate        *x509.Certificate
	caKey                *ecdsa.PrivateKey
	serverX509           *x509.Certificate
}

func generateTestRootCA(t *testing.T, commonName string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
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

func generateTestSignedCertificate(t *testing.T, commonName string, caCertificate *x509.Certificate, caKey *ecdsa.PrivateKey, extendedKeyUsage x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{extendedKeyUsage},
	}
	certificateBytes, err := x509.CreateCertificate(rand.Reader, template, caCertificate, &privateKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedCertificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		t.Fatal(err)
	}
	return parsedCertificate, privateKey
}

func encodeTestCRLSigned(
	t *testing.T,
	issuerCertificate *x509.Certificate,
	signerKey *ecdsa.PrivateKey,
	revokedCertificates []*x509.Certificate,
	thisUpdate time.Time,
	nextUpdate time.Time,
) []byte {
	t.Helper()
	revokedEntries := make([]x509.RevocationListEntry, 0, len(revokedCertificates))
	for _, revokedCertificate := range revokedCertificates {
		revokedEntries = append(revokedEntries, x509.RevocationListEntry{
			SerialNumber:   revokedCertificate.SerialNumber,
			RevocationTime: thisUpdate,
		})
	}
	template := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: revokedEntries,
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, issuerCertificate, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
}

func writeTestCRLSigned(
	t *testing.T,
	crlPath string,
	issuerCertificate *x509.Certificate,
	signerKey *ecdsa.PrivateKey,
	revokedCertificates []*x509.Certificate,
	thisUpdate time.Time,
	nextUpdate time.Time,
) {
	t.Helper()
	crlPEM := encodeTestCRLSigned(t, issuerCertificate, signerKey, revokedCertificates, thisUpdate, nextUpdate)
	err := os.WriteFile(crlPath, crlPEM, 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

func writeTestCRLHandshakeMaterial(t *testing.T) crlHandshakeMaterial {
	t.Helper()
	temporaryDirectory := t.TempDir()
	caCertificate, caKey := generateTestRootCA(t, "openvpn-test-root")
	serverCertificate, serverKey := generateTestSignedCertificate(
		t, "openvpn-crl-test-server", caCertificate, caKey, x509.ExtKeyUsageServerAuth)
	clientCertificate, clientKey := generateTestSignedCertificate(
		t, "openvpn-crl-test-client", caCertificate, caKey, x509.ExtKeyUsageClientAuth)
	return crlHandshakeMaterial{
		certificateAuthority: Material{Path: writeTestPEM(t, temporaryDirectory, "ca.crt", "CERTIFICATE", caCertificate.Raw)},
		serverCertificate:    Material{Path: writeTestPEM(t, temporaryDirectory, "server.crt", "CERTIFICATE", serverCertificate.Raw)},
		serverKey:            Material{Path: writeTestPKCS8Key(t, temporaryDirectory, "server.key", serverKey)},
		clientCertificate:    Material{Path: writeTestPEM(t, temporaryDirectory, "client.crt", "CERTIFICATE", clientCertificate.Raw)},
		clientKey:            Material{Path: writeTestPKCS8Key(t, temporaryDirectory, "client.key", clientKey)},
		caCertificate:        caCertificate,
		caKey:                caKey,
		serverX509:           serverCertificate,
	}
}

func assertClientCRLRejectsHandshake(t *testing.T, material crlHandshakeMaterial, crlPath string) {
	t.Helper()
	listenAddress := reserveListenAddressForProtocol(t, "udp")
	authenticatorCalled := make(chan struct{}, 1)
	server, err := NewServer(ServerOptions{
		NewOutboundQueue: newTestOutboundQueue,
		Context:          context.Background(),
		Mode:             ModeTLS,
		Transport: ServerTransportOptions{
			ListenAddress: listenAddress,
			Protocol:      "udp",
		},
		TLS: ServerTLSOptions{
			CertificateAuthority: material.certificateAuthority,
			Certificate:          material.serverCertificate,
			Key:                  material.serverKey,
		},
		Authentication: ServerAuthenticationOptions{Authenticator: func(ctx context.Context, username string, password string) error {
			_, _, _ = ctx, username, password
			select {
			case authenticatorCalled <- struct{}{}:
			default:
			}
			return nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}
	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelClientContext()
	client, err := NewClient(ClientOptions{
		Context:   clientContext,
		Mode:      ModeTLS,
		Transport: clientTransportOptions(t, listenAddress, "udp"),
		TLS: ClientTLSOptions{
			CertificateAuthority: material.certificateAuthority,
			Certificate:          material.clientCertificate,
			Key:                  material.clientKey,
			CRLVerify:            crlPath,
		},
		Authentication: ClientAuthenticationOptions{
			Username: "crl-user",
			Password: "crl-password",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	readContext, cancelRead := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelRead()
	_, err = client.ReadDataPacket(readContext)
	if err == nil {
		t.Fatal("expected client CRL rejection, got data packet")
	}
	if client.Ready() {
		t.Fatal("client became ready after client CRL rejection")
	}
	select {
	case <-authenticatorCalled:
		t.Fatal("server authenticator ran after CRL rejection")
	default:
	}
}

func assertClientCRLAcceptsHandshake(t *testing.T, material crlHandshakeMaterial, crlPath string) {
	t.Helper()
	listenAddress := reserveListenAddressForProtocol(t, "udp")
	authenticatorCalled := make(chan struct{}, 1)
	server, err := NewServer(ServerOptions{
		NewOutboundQueue: newTestOutboundQueue,
		Context:          context.Background(),
		Mode:             ModeTLS,
		Transport: ServerTransportOptions{
			ListenAddress: listenAddress,
			Protocol:      "udp",
		},
		TLS: ServerTLSOptions{
			CertificateAuthority: material.certificateAuthority,
			Certificate:          material.serverCertificate,
			Key:                  material.serverKey,
		},
		Authentication: ServerAuthenticationOptions{Authenticator: func(ctx context.Context, username string, password string) error {
			_, _, _ = ctx, username, password
			select {
			case authenticatorCalled <- struct{}{}:
			default:
			}
			return nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}
	clientContext, cancelClientContext := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelClientContext()
	client, err := NewClient(ClientOptions{
		Context:   clientContext,
		Mode:      ModeTLS,
		Transport: clientTransportOptions(t, listenAddress, "udp"),
		TLS: ClientTLSOptions{
			CertificateAuthority: material.certificateAuthority,
			Certificate:          material.clientCertificate,
			Key:                  material.clientKey,
			CRLVerify:            crlPath,
		},
		Authentication: ClientAuthenticationOptions{
			Username: "crl-user",
			Password: "crl-password",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	waitForClientReady(t, client, 5*time.Second)
	select {
	case <-authenticatorCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("server authenticator was not called")
	}
}

func TestVerifyAgainstCRLAllowsNonRevokedCertificate(t *testing.T) {
	t.Parallel()
	material := writeTestCRLHandshakeMaterial(t)
	crlPath := filepath.Join(t.TempDir(), "valid.crl.pem")
	writeTestCRLSigned(
		t,
		crlPath,
		material.caCertificate,
		material.caKey,
		nil,
		time.Now().Add(-time.Minute),
		time.Now().Add(24*time.Hour),
	)
	assertClientCRLAcceptsHandshake(t, material, crlPath)
}

func TestVerifyAgainstCRLRejectsRevokedCertificate(t *testing.T) {
	t.Parallel()
	material := writeTestCRLHandshakeMaterial(t)

	temporaryDirectory := t.TempDir()
	crlPath := filepath.Join(temporaryDirectory, "revoked.crl.pem")
	writeTestCRLSigned(
		t,
		crlPath,
		material.caCertificate,
		material.caKey,
		[]*x509.Certificate{material.serverX509},
		time.Now().Add(-time.Minute),
		time.Now().Add(24*time.Hour),
	)
	assertClientCRLRejectsHandshake(t, material, crlPath)
}

func TestVerifyAgainstCRLRejectsForgedSignature(t *testing.T) {
	t.Parallel()
	material := writeTestCRLHandshakeMaterial(t)
	_, rogueKey := generateTestRootCA(t, "openvpn-test-rogue-root")

	temporaryDirectory := t.TempDir()
	crlPath := filepath.Join(temporaryDirectory, "forged.crl.pem")
	writeTestCRLSigned(
		t,
		crlPath,
		material.caCertificate,
		rogueKey,
		[]*x509.Certificate{material.serverX509},
		time.Now().Add(-time.Minute),
		time.Now().Add(24*time.Hour),
	)
	assertClientCRLRejectsHandshake(t, material, crlPath)
}

func TestVerifyAgainstCRLRejectsExpiredCRL(t *testing.T) {
	t.Parallel()
	material := writeTestCRLHandshakeMaterial(t)

	temporaryDirectory := t.TempDir()
	crlPath := filepath.Join(temporaryDirectory, "expired.crl.pem")
	writeTestCRLSigned(
		t,
		crlPath,
		material.caCertificate,
		material.caKey,
		nil,
		time.Now().Add(-24*time.Hour),
		time.Now().Add(-time.Hour),
	)
	assertClientCRLRejectsHandshake(t, material, crlPath)
}

func TestVerifyAgainstCRLRejectsCRLBeforeThisUpdate(t *testing.T) {
	t.Parallel()
	material := writeTestCRLHandshakeMaterial(t)

	temporaryDirectory := t.TempDir()
	crlPath := filepath.Join(temporaryDirectory, "premature.crl.pem")
	writeTestCRLSigned(
		t,
		crlPath,
		material.caCertificate,
		material.caKey,
		nil,
		time.Now().Add(time.Hour),
		time.Now().Add(24*time.Hour),
	)
	assertClientCRLRejectsHandshake(t, material, crlPath)
}

type crlBundleHandshakeMaterial struct {
	handshake          crlHandshakeMaterial
	firstAuthority     *x509.Certificate
	firstAuthorityKey  *ecdsa.PrivateKey
	secondAuthority    *x509.Certificate
	secondAuthorityKey *ecdsa.PrivateKey
}

// The peer being verified is issued by the first authority and the local
// certificate by the second, so both authorities of the --ca bundle are in use
// and only one of the two CRLs covers the verified chain.
func writeTestCRLBundleHandshakeMaterial(t *testing.T) crlBundleHandshakeMaterial {
	t.Helper()
	temporaryDirectory := t.TempDir()
	firstAuthority, firstAuthorityKey := generateTestRootCA(t, "openvpn-crl-bundle-first-root")
	secondAuthority, secondAuthorityKey := generateTestRootCA(t, "openvpn-crl-bundle-second-root")
	serverCertificate, serverKey := generateTestSignedCertificate(
		t, "openvpn-crl-bundle-server", firstAuthority, firstAuthorityKey, x509.ExtKeyUsageServerAuth)
	clientCertificate, clientKey := generateTestSignedCertificate(
		t, "openvpn-crl-bundle-client", secondAuthority, secondAuthorityKey, x509.ExtKeyUsageClientAuth)
	certificateAuthorityPath := writeTestPEMBundle(t, filepath.Join(temporaryDirectory, "ca-bundle.crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: firstAuthority.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: secondAuthority.Raw}),
	)
	return crlBundleHandshakeMaterial{
		handshake: crlHandshakeMaterial{
			certificateAuthority: Material{Path: certificateAuthorityPath},
			serverCertificate:    Material{Path: writeTestPEM(t, temporaryDirectory, "server.crt", "CERTIFICATE", serverCertificate.Raw)},
			serverKey:            Material{Path: writeTestPKCS8Key(t, temporaryDirectory, "server.key", serverKey)},
			clientCertificate:    Material{Path: writeTestPEM(t, temporaryDirectory, "client.crt", "CERTIFICATE", clientCertificate.Raw)},
			clientKey:            Material{Path: writeTestPKCS8Key(t, temporaryDirectory, "client.key", clientKey)},
			caCertificate:        firstAuthority,
			caKey:                firstAuthorityKey,
			serverX509:           serverCertificate,
		},
		firstAuthority:     firstAuthority,
		firstAuthorityKey:  firstAuthorityKey,
		secondAuthority:    secondAuthority,
		secondAuthorityKey: secondAuthorityKey,
	}
}

func TestVerifyAgainstCRLBundleAppliesTheEntryIssuedByThePeerAuthority(t *testing.T) {
	t.Parallel()
	material := writeTestCRLBundleHandshakeMaterial(t)
	thisUpdate := time.Now().Add(-time.Minute)
	nextUpdate := time.Now().Add(24 * time.Hour)
	peerAuthorityEntry := encodeTestCRLSigned(
		t, material.firstAuthority, material.firstAuthorityKey, nil, thisUpdate, nextUpdate)
	peerAuthorityRevokingEntry := encodeTestCRLSigned(
		t, material.firstAuthority, material.firstAuthorityKey,
		[]*x509.Certificate{material.handshake.serverX509}, thisUpdate, nextUpdate)
	otherAuthorityEntry := encodeTestCRLSigned(
		t, material.secondAuthority, material.secondAuthorityKey, nil, thisUpdate, nextUpdate)

	t.Run("accepts_peer_while_a_foreign_entry_leads_the_bundle", func(t *testing.T) {
		crlPath := writeTestPEMBundle(t, filepath.Join(t.TempDir(), "crl-bundle.pem"), otherAuthorityEntry, peerAuthorityEntry)
		assertClientCRLAcceptsHandshake(t, material.handshake, crlPath)
	})
	t.Run("rejects_peer_revoked_by_the_leading_entry", func(t *testing.T) {
		crlPath := writeTestPEMBundle(t, filepath.Join(t.TempDir(), "crl-bundle.pem"), peerAuthorityRevokingEntry, otherAuthorityEntry)
		assertClientCRLRejectsHandshake(t, material.handshake, crlPath)
	})
	t.Run("rejects_peer_revoked_by_the_trailing_entry", func(t *testing.T) {
		crlPath := writeTestPEMBundle(t, filepath.Join(t.TempDir(), "crl-bundle.pem"), otherAuthorityEntry, peerAuthorityRevokingEntry)
		assertClientCRLRejectsHandshake(t, material.handshake, crlPath)
	})
	t.Run("rejects_peer_whose_authority_has_no_entry", func(t *testing.T) {
		crlPath := writeTestPEMBundle(t, filepath.Join(t.TempDir(), "crl-bundle.pem"), otherAuthorityEntry)
		assertClientCRLRejectsHandshake(t, material.handshake, crlPath)
	})
}
