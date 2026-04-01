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

func generateTestRootCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "openvpn-test-root"},
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
	pemBuffer := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	err = os.WriteFile(crlPath, pemBuffer, 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

func writeTestCRLHandshakeMaterial(t *testing.T) crlHandshakeMaterial {
	t.Helper()
	temporaryDirectory := t.TempDir()
	caCertificate, caKey := generateTestRootCA(t)
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
		Context: context.Background(),
		Mode:    ModeTLS,
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

func TestVerifyAgainstCRLAllowsNonRevokedCertificate(t *testing.T) {
	material := writeTestCRLHandshakeMaterial(t)
	temporaryDirectory := t.TempDir()
	crlPath := filepath.Join(temporaryDirectory, "valid.crl.pem")
	writeTestCRLSigned(
		t,
		crlPath,
		material.caCertificate,
		material.caKey,
		nil,
		time.Now().Add(-time.Minute),
		time.Now().Add(24*time.Hour),
	)
	listenAddress := reserveListenAddressForProtocol(t, "udp")
	authenticatorCalled := make(chan struct{}, 1)
	server, err := NewServer(ServerOptions{
		Context: context.Background(),
		Mode:    ModeTLS,
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

func TestVerifyAgainstCRLRejectsRevokedCertificate(t *testing.T) {
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
	material := writeTestCRLHandshakeMaterial(t)
	_, rogueKey := generateTestRootCA(t)

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
