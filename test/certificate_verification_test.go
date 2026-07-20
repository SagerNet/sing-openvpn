package test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/netip"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
)

type certificateVerificationMaterial struct {
	certificateAuthority openvpn.Material
	serverCertificate    openvpn.Material
	serverKey            openvpn.Material
	clientCertificate    openvpn.Material
	clientKey            openvpn.Material
}

type certificateVerificationParameters struct {
	authorityKey               crypto.Signer
	authoritySignature         x509.SignatureAlgorithm
	serverKey                  crypto.Signer
	serverSignature            x509.SignatureAlgorithm
	serverKeyUsage             x509.KeyUsage
	serverExtendedKeyUsage     []x509.ExtKeyUsage
	serverUnknownExtendedUsage []asn1.ObjectIdentifier
	clientKey                  crypto.Signer
	clientSignature            x509.SignatureAlgorithm
}

type certificateVerificationResult uint8

const (
	certificateVerificationAccepted certificateVerificationResult = iota
	certificateVerificationRejectedByClient
	certificateVerificationRejectedByServer
)

func TestRemoteCertificateUsageIntegration(t *testing.T) {
	rsaAuthority := generateRSASigner(t, 2048)
	t.Run("missing_key_usage_rejected_by_shorthand", func(t *testing.T) {
		material := createCertificateVerificationMaterial(t, certificateVerificationParameters{
			authorityKey:           rsaAuthority,
			authoritySignature:     x509.SHA256WithRSA,
			serverKey:              generateRSASigner(t, 2048),
			serverSignature:        x509.SHA256WithRSA,
			serverExtendedKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		runCertificateVerificationSession(t, material,
			openvpn.ClientTLSOptions{RemoteCertificateTLS: "server"},
			openvpn.ServerTLSOptions{VerifyClientCertificate: "none"},
			certificateVerificationRejectedByClient,
		)
	})
	t.Run("missing_key_usage_allowed_without_shorthand", func(t *testing.T) {
		material := createCertificateVerificationMaterial(t, certificateVerificationParameters{
			authorityKey:           rsaAuthority,
			authoritySignature:     x509.SHA256WithRSA,
			serverKey:              generateRSASigner(t, 2048),
			serverSignature:        x509.SHA256WithRSA,
			serverExtendedKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		runCertificateVerificationSession(t, material,
			openvpn.ClientTLSOptions{},
			openvpn.ServerTLSOptions{VerifyClientCertificate: "none"},
			certificateVerificationAccepted,
		)
	})
	t.Run("key_usage_masks_are_alternatives", func(t *testing.T) {
		material := createCertificateVerificationMaterial(t, certificateVerificationParameters{
			authorityKey:           rsaAuthority,
			authoritySignature:     x509.SHA256WithRSA,
			serverKey:              generateRSASigner(t, 2048),
			serverSignature:        x509.SHA256WithRSA,
			serverKeyUsage:         x509.KeyUsageDigitalSignature,
			serverExtendedKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		runCertificateVerificationSession(t, material,
			openvpn.ClientTLSOptions{RemoteCertificateKU: []string{"20", "80"}},
			openvpn.ServerTLSOptions{VerifyClientCertificate: "none"},
			certificateVerificationAccepted,
		)
	})
	t.Run("custom_extended_key_usage_oid", func(t *testing.T) {
		customUsage := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 7}
		material := createCertificateVerificationMaterial(t, certificateVerificationParameters{
			authorityKey:               rsaAuthority,
			authoritySignature:         x509.SHA256WithRSA,
			serverKey:                  generateRSASigner(t, 2048),
			serverSignature:            x509.SHA256WithRSA,
			serverKeyUsage:             x509.KeyUsageDigitalSignature,
			serverUnknownExtendedUsage: []asn1.ObjectIdentifier{customUsage},
		})
		runCertificateVerificationSession(t, material,
			openvpn.ClientTLSOptions{RemoteCertificateEKU: customUsage.String()},
			openvpn.ServerTLSOptions{VerifyClientCertificate: "none"},
			certificateVerificationAccepted,
		)
	})
	t.Run("openssl_extended_key_usage_name", func(t *testing.T) {
		material := createCertificateVerificationMaterial(t, certificateVerificationParameters{
			authorityKey:           rsaAuthority,
			authoritySignature:     x509.SHA256WithRSA,
			serverKey:              generateRSASigner(t, 2048),
			serverSignature:        x509.SHA256WithRSA,
			serverKeyUsage:         x509.KeyUsageDigitalSignature,
			serverExtendedKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		runCertificateVerificationSession(t, material,
			openvpn.ClientTLSOptions{RemoteCertificateEKU: "TLS Web Server Authentication"},
			openvpn.ServerTLSOptions{VerifyClientCertificate: "none"},
			certificateVerificationAccepted,
		)
	})
}

func TestCertificateProfileIntegration(t *testing.T) {
	rsaAuthority := generateRSASigner(t, 2048)
	sha1Material := createCertificateVerificationMaterial(t, certificateVerificationParameters{
		authorityKey:           rsaAuthority,
		authoritySignature:     x509.SHA256WithRSA,
		serverKey:              generateRSASigner(t, 2048),
		serverSignature:        x509.SHA1WithRSA,
		serverKeyUsage:         x509.KeyUsageDigitalSignature,
		serverExtendedKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	for _, profile := range []string{"insecure", "legacy"} {
		t.Run("sha1_allowed_by_"+profile, func(t *testing.T) {
			runCertificateVerificationSession(t, sha1Material,
				openvpn.ClientTLSOptions{CertificateProfile: profile},
				openvpn.ServerTLSOptions{VerifyClientCertificate: "none"},
				certificateVerificationAccepted,
			)
		})
	}
	for _, profile := range []string{"preferred", "suiteb"} {
		t.Run("sha1_rejected_by_"+profile, func(t *testing.T) {
			runCertificateVerificationSession(t, sha1Material,
				openvpn.ClientTLSOptions{CertificateProfile: profile},
				openvpn.ServerTLSOptions{VerifyClientCertificate: "none"},
				certificateVerificationRejectedByClient,
			)
		})
	}
	rsa1024Material := createCertificateVerificationMaterial(t, certificateVerificationParameters{
		authorityKey:           rsaAuthority,
		authoritySignature:     x509.SHA256WithRSA,
		serverKey:              generateRSASigner(t, 1024),
		serverSignature:        x509.SHA256WithRSA,
		serverKeyUsage:         x509.KeyUsageDigitalSignature,
		serverExtendedKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	t.Run("rsa_1024_allowed_by_insecure", func(t *testing.T) {
		runCertificateVerificationSession(t, rsa1024Material,
			openvpn.ClientTLSOptions{CertificateProfile: "insecure"},
			openvpn.ServerTLSOptions{VerifyClientCertificate: "none", CertificateProfile: "insecure"},
			certificateVerificationAccepted,
		)
	})
	t.Run("rsa_1024_allowed_by_legacy", func(t *testing.T) {
		runCertificateVerificationSession(t, rsa1024Material,
			openvpn.ClientTLSOptions{CertificateProfile: "legacy"},
			openvpn.ServerTLSOptions{VerifyClientCertificate: "none", CertificateProfile: "legacy"},
			certificateVerificationAccepted,
		)
	})
	t.Run("rsa_1024_rejected_by_preferred", func(t *testing.T) {
		runCertificateVerificationSession(t, rsa1024Material,
			openvpn.ClientTLSOptions{CertificateProfile: "preferred"},
			openvpn.ServerTLSOptions{VerifyClientCertificate: "none", CertificateProfile: "insecure"},
			certificateVerificationRejectedByClient,
		)
	})
	preferredMaterial := createCertificateVerificationMaterial(t, certificateVerificationParameters{
		authorityKey:           rsaAuthority,
		authoritySignature:     x509.SHA256WithRSA,
		serverKey:              generateRSASigner(t, 2048),
		serverSignature:        x509.SHA256WithRSA,
		serverKeyUsage:         x509.KeyUsageDigitalSignature,
		serverExtendedKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	t.Run("preferred_rsa_sha256", func(t *testing.T) {
		runCertificateVerificationSession(t, preferredMaterial,
			openvpn.ClientTLSOptions{CertificateProfile: "preferred"},
			openvpn.ServerTLSOptions{VerifyClientCertificate: "none"},
			certificateVerificationAccepted,
		)
	})
	ecdsaAuthority := generateECDSASigner(t)
	suiteBMaterial := createCertificateVerificationMaterial(t, certificateVerificationParameters{
		authorityKey:           ecdsaAuthority,
		authoritySignature:     x509.ECDSAWithSHA256,
		serverKey:              generateECDSASigner(t),
		serverSignature:        x509.ECDSAWithSHA256,
		serverKeyUsage:         x509.KeyUsageDigitalSignature,
		serverExtendedKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	t.Run("suiteb_ecdsa_p256", func(t *testing.T) {
		runCertificateVerificationSession(t, suiteBMaterial,
			openvpn.ClientTLSOptions{CertificateProfile: "suiteb"},
			openvpn.ServerTLSOptions{VerifyClientCertificate: "none"},
			certificateVerificationAccepted,
		)
	})
}

func TestServerCertificateProfileIntegration(t *testing.T) {
	rsaAuthority := generateRSASigner(t, 2048)
	material := createCertificateVerificationMaterial(t, certificateVerificationParameters{
		authorityKey:           rsaAuthority,
		authoritySignature:     x509.SHA256WithRSA,
		serverKey:              generateRSASigner(t, 2048),
		serverSignature:        x509.SHA256WithRSA,
		serverKeyUsage:         x509.KeyUsageDigitalSignature,
		serverExtendedKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		clientKey:              generateRSASigner(t, 2048),
		clientSignature:        x509.SHA1WithRSA,
	})
	t.Run("legacy_accepts_sha1_client", func(t *testing.T) {
		runCertificateVerificationSession(t, material,
			openvpn.ClientTLSOptions{Certificate: material.clientCertificate, Key: material.clientKey},
			openvpn.ServerTLSOptions{CertificateProfile: "legacy"},
			certificateVerificationAccepted,
		)
	})
	t.Run("preferred_rejects_sha1_client", func(t *testing.T) {
		runCertificateVerificationSession(t, material,
			openvpn.ClientTLSOptions{Certificate: material.clientCertificate, Key: material.clientKey},
			openvpn.ServerTLSOptions{CertificateProfile: "preferred"},
			certificateVerificationRejectedByServer,
		)
	})
}

func runCertificateVerificationSession(t *testing.T, material certificateVerificationMaterial, clientTLS openvpn.ClientTLSOptions, serverTLS openvpn.ServerTLSOptions, expectedResult certificateVerificationResult) {
	t.Helper()
	listenAddress := reserveListenAddressForProtocol(t, "udp")
	serverTLS.CertificateAuthority = material.certificateAuthority
	serverTLS.Certificate = material.serverCertificate
	serverTLS.Key = material.serverKey
	server, err := openvpn.NewServer(openvpn.ServerOptions{
		Context: context.Background(),
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ServerTransportOptions{
			ListenAddress: listenAddress,
			Protocol:      "udp",
		},
		TLS: serverTLS,
		Tunnel: openvpn.ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.91.0.0/24")},
			Topology:     "subnet",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}
	clientTLS.CertificateAuthority = material.certificateAuthority
	clientContext, cancelClient := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancelClient)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context:   clientContext,
		Mode:      openvpn.ModeTLS,
		Transport: clientTransportOptions(t, listenAddress, "udp"),
		TLS:       clientTLS,
		Pull:      openvpn.ClientPullOptions{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	switch expectedResult {
	case certificateVerificationAccepted:
		waitForClientReady(t, client, 5*time.Second)
	case certificateVerificationRejectedByClient:
		waitForClientTerminalError(t, client, 5*time.Second, openvpn.ErrPeerCertificateVerification)
	case certificateVerificationRejectedByServer:
		assertClientRemainsNotReady(t, client, time.Second)
	default:
		t.Fatal("unknown expected certificate verification result")
	}
}

func assertClientRemainsNotReady(t *testing.T, client *openvpn.Client, duration time.Duration) {
	t.Helper()
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		if client.Ready() {
			t.Fatal("client became ready after the server should have rejected its certificate")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func createCertificateVerificationMaterial(t *testing.T, parameters certificateVerificationParameters) certificateVerificationMaterial {
	t.Helper()
	directory := t.TempDir()
	authorityTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "openvpn-verification-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    parameters.authoritySignature,
	}
	authorityDER, err := x509.CreateCertificate(rand.Reader, authorityTemplate, authorityTemplate, parameters.authorityKey.Public(), parameters.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	authorityCertificate, err := x509.ParseCertificate(authorityDER)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber:       big.NewInt(2),
		Subject:            pkix.Name{CommonName: "openvpn-verification-server"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		KeyUsage:           parameters.serverKeyUsage,
		ExtKeyUsage:        parameters.serverExtendedKeyUsage,
		UnknownExtKeyUsage: parameters.serverUnknownExtendedUsage,
		SignatureAlgorithm: parameters.serverSignature,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, authorityCertificate, parameters.serverKey.Public(), parameters.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	material := certificateVerificationMaterial{
		certificateAuthority: openvpn.Material{Path: writeTestPEM(t, directory, "ca.crt", "CERTIFICATE", authorityDER)},
		serverCertificate:    openvpn.Material{Path: writeTestPEM(t, directory, "server.crt", "CERTIFICATE", serverDER)},
		serverKey:            openvpn.Material{Path: writeCertificateVerificationKey(t, directory, "server.key", parameters.serverKey)},
	}
	if parameters.clientKey == nil {
		return material
	}
	clientTemplate := &x509.Certificate{
		SerialNumber:       big.NewInt(3),
		Subject:            pkix.Name{CommonName: "openvpn-verification-client"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SignatureAlgorithm: parameters.clientSignature,
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, authorityCertificate, parameters.clientKey.Public(), parameters.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	material.clientCertificate = openvpn.Material{Path: writeTestPEM(t, directory, "client.crt", "CERTIFICATE", clientDER)}
	material.clientKey = openvpn.Material{Path: writeCertificateVerificationKey(t, directory, "client.key", parameters.clientKey)}
	return material
}

func writeCertificateVerificationKey(t *testing.T, directory string, fileName string, privateKey crypto.Signer) string {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return writeTestPEM(t, directory, fileName, "PRIVATE KEY", keyDER)
}

func generateRSASigner(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey
}

func generateECDSASigner(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey
}
