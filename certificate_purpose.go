package openvpn

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// OpenSSL x509v3_cache_extensions caches these three extensions, and every
// X509_PURPOSE check rejects a certificate only through an extension the
// certificate actually carries: a certificate omitting all three satisfies
// every purpose.
type certificateUsageExtensions struct {
	keyUsagePresent         bool
	keyUsage                uint
	extendedKeyUsagePresent bool
	extendedKeyUsage        uint
	netscapeCertTypePresent bool
	netscapeCertType        byte
}

// OpenSSL ku_reject / xku_reject / ns_reject.
func (u certificateUsageExtensions) rejectsKeyUsage(accepted uint) bool {
	return u.keyUsagePresent && u.keyUsage&accepted == 0
}

func (u certificateUsageExtensions) rejectsExtendedKeyUsage(accepted uint) bool {
	return u.extendedKeyUsagePresent && u.extendedKeyUsage&accepted == 0
}

func (u certificateUsageExtensions) rejectsNetscapeCertType(accepted byte) bool {
	return u.netscapeCertTypePresent && u.netscapeCertType&accepted == 0
}

// OpenSSL KU_* bit layout of the cached id-ce-keyUsage extension.
const (
	openSSLKeyUsageDigitalSignature = 0x0080
	openSSLKeyUsageKeyEncipherment  = 0x0020
	openSSLKeyUsageKeyAgreement     = 0x0008
)

// OpenSSL XKU_* bits; only the TLS ones separate the purposes implemented
// here, every other key purpose OID behaves like an unrecognized one.
const (
	openSSLExtendedKeyUsageSSLServer         = 0x01
	openSSLExtendedKeyUsageSSLClient         = 0x02
	openSSLExtendedKeyUsageServerGatedCrypto = 0x10
)

// OpenSSL NS_SSL_CA, checked by check_ssl_ca.
const netscapeCertTypeSSLCertificateAuthority = 0x04

var openSSLExtendedKeyUsageBits = []struct {
	identifier asn1.ObjectIdentifier
	bit        uint
}{
	{serverAuthOID, openSSLExtendedKeyUsageSSLServer},
	{clientAuthOID, openSSLExtendedKeyUsageSSLClient},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}, openSSLExtendedKeyUsageServerGatedCrypto},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}, openSSLExtendedKeyUsageServerGatedCrypto},
}

// OpenSSL X509_PURPOSE_SSL_CLIENT / X509_PURPOSE_SSL_SERVER. OpenSSL's
// ssl_verify_cert_chain selects the purpose from the local role, so a peer
// acting as a client is checked against ssl_client and a peer acting as a
// server against ssl_server, independently of --remote-cert-eku.
type certificatePurpose int

const (
	certificatePurposeSSLClient certificatePurpose = 1
	certificatePurposeSSLServer certificatePurpose = 2
)

// OpenSSL check_purpose_ssl_client / check_purpose_ssl_server, with
// requireCertificateAuthority selecting check_ssl_ca as check_chain does for
// every certificate above the leaf.
func checkCertificatePurpose(certificate *x509.Certificate, purpose certificatePurpose, requireCertificateAuthority bool) (bool, error) {
	usage, err := readCertificateUsageExtensions(certificate)
	if err != nil {
		return false, err
	}
	switch purpose {
	case certificatePurposeSSLClient:
		if usage.rejectsExtendedKeyUsage(openSSLExtendedKeyUsageSSLClient) {
			return false, nil
		}
		if requireCertificateAuthority {
			return !usage.rejectsNetscapeCertType(netscapeCertTypeSSLCertificateAuthority), nil
		}
		if usage.rejectsKeyUsage(openSSLKeyUsageDigitalSignature | openSSLKeyUsageKeyAgreement) {
			return false, nil
		}
		return !usage.rejectsNetscapeCertType(netscapeCertTypeSSLClient), nil
	case certificatePurposeSSLServer:
		if usage.rejectsExtendedKeyUsage(openSSLExtendedKeyUsageSSLServer | openSSLExtendedKeyUsageServerGatedCrypto) {
			return false, nil
		}
		if requireCertificateAuthority {
			return !usage.rejectsNetscapeCertType(netscapeCertTypeSSLCertificateAuthority), nil
		}
		if usage.rejectsNetscapeCertType(netscapeCertTypeSSLServer) {
			return false, nil
		}
		return !usage.rejectsKeyUsage(openSSLKeyUsageDigitalSignature | openSSLKeyUsageKeyEncipherment | openSSLKeyUsageKeyAgreement), nil
	default:
		return false, nil
	}
}

// OpenSSL check_chain applies the store purpose to every chain member, with
// the trust anchor and the intermediates reduced to check_ssl_ca.
func filterChainsByCertificatePurpose(verifiedChains [][]*x509.Certificate, purpose certificatePurpose) ([][]*x509.Certificate, error) {
	matchedChains := make([][]*x509.Certificate, 0, len(verifiedChains))
	for _, chain := range verifiedChains {
		chainMatched := true
		for certificateIndex, chainCertificate := range chain {
			matched, err := checkCertificatePurpose(chainCertificate, purpose, certificateIndex > 0)
			if err != nil {
				return nil, err
			}
			if !matched {
				chainMatched = false
				break
			}
		}
		if chainMatched {
			matchedChains = append(matchedChains, chain)
		}
	}
	if len(matchedChains) == 0 {
		return nil, ErrPeerCertificatePurpose
	}
	return matchedChains, nil
}

func readCertificateUsageExtensions(certificate *x509.Certificate) (certificateUsageExtensions, error) {
	var usage certificateUsageExtensions
	for _, extension := range certificate.Extensions {
		switch {
		case extension.Id.Equal(keyUsageExtensionOID):
			bits, err := readOpenSSLBitString(extension)
			if err != nil {
				return certificateUsageExtensions{}, err
			}
			usage.keyUsagePresent = true
			if len(bits) > 0 {
				usage.keyUsage = uint(bits[0])
			}
			if len(bits) > 1 {
				usage.keyUsage |= uint(bits[1]) << 8
			}
		case extension.Id.Equal(extendedKeyUsageExtensionOID):
			var keyPurposes []asn1.ObjectIdentifier
			_, err := asn1.Unmarshal(extension.Value, &keyPurposes)
			if err != nil {
				return certificateUsageExtensions{}, err
			}
			usage.extendedKeyUsagePresent = true
			for _, keyPurpose := range keyPurposes {
				for _, knownKeyPurpose := range openSSLExtendedKeyUsageBits {
					if knownKeyPurpose.identifier.Equal(keyPurpose) {
						usage.extendedKeyUsage |= knownKeyPurpose.bit
					}
				}
			}
		case extension.Id.Equal(netscapeCertTypeExtensionOID):
			bits, err := readOpenSSLBitString(extension)
			if err != nil {
				return certificateUsageExtensions{}, err
			}
			usage.netscapeCertTypePresent = true
			if len(bits) > 0 {
				usage.netscapeCertType = bits[0]
			}
		}
	}
	return usage, nil
}

// OpenSSL X509V3_EXT_d2i ignores data after the value, and
// c2i_ASN1_BIT_STRING clears the unused bits instead of rejecting them.
func readOpenSSLBitString(extension pkix.Extension) ([]byte, error) {
	var bits cryptobyte.String
	value := cryptobyte.String(extension.Value)
	if !value.ReadASN1(&bits, cryptobyte_asn1.BIT_STRING) || len(bits) == 0 || bits[0] > 7 {
		return nil, E.New("invalid BIT STRING in certificate extension ", extension.Id)
	}
	unusedBits := bits[0]
	cleared := bytes.Clone(bits[1:])
	if len(cleared) > 0 {
		cleared[len(cleared)-1] &= 0xff << unusedBits
	}
	return cleared, nil
}
