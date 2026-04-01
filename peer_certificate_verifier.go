package openvpn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"os"
	"slices"
	"strconv"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

type peerCertificateVerifierOptions struct {
	Roots                    *x509.CertPool
	KeyUsage                 x509.ExtKeyUsage
	VerifyName               string
	VerifyNameType           string
	PeerFingerprints         []string
	CRLPath                  string
	RequiredKeyUsage         uint
	RequireKeyUsageExtension bool
	RequiredExtendedUsage    []x509.ExtKeyUsage
	NSCertificateType        string
	CertificateProfile       string
}

type peerCertificateVerifier struct {
	options peerCertificateVerifierOptions
}

func (v *peerCertificateVerifier) Verify(rawCertificates [][]byte) error {
	if len(rawCertificates) == 0 {
		return E.New("missing peer certificate")
	}
	peerCertificates := make([]*x509.Certificate, 0, len(rawCertificates))
	for _, rawCertificate := range rawCertificates {
		peerCertificate, err := x509.ParseCertificate(rawCertificate)
		if err != nil {
			return err
		}
		peerCertificates = append(peerCertificates, peerCertificate)
	}
	// Upstream options_postprocess_verify / tls_ctx_load_ca skip chain
	// verification when --peer-fingerprint is used without --ca.
	fingerprintOnly := v.options.Roots == nil && len(v.options.PeerFingerprints) > 0
	var verifiedChains [][]*x509.Certificate
	if fingerprintOnly {
		now := time.Now()
		if now.Before(peerCertificates[0].NotBefore) {
			return E.New("peer certificate not yet valid")
		}
		if now.After(peerCertificates[0].NotAfter) {
			return E.New("peer certificate has expired")
		}
		// Upstream verify_cert still applies profile and usage checks.
		verifiedChains = [][]*x509.Certificate{{peerCertificates[0]}}
	} else {
		intermediates := x509.NewCertPool()
		for _, peerCertificate := range peerCertificates[1:] {
			intermediates.AddCert(peerCertificate)
		}
		verifyOptions := x509.VerifyOptions{
			Roots:         v.options.Roots,
			Intermediates: intermediates,
		}
		verifyOptions.KeyUsages = []x509.ExtKeyUsage{v.options.KeyUsage}
		var err error
		verifiedChains, err = peerCertificates[0].Verify(verifyOptions)
		if err != nil {
			return err
		}
	}
	err := enforceCertificateProfile(verifiedChains, v.options.CertificateProfile)
	if err != nil {
		return err
	}
	err = verifyX509NameMatch(peerCertificates[0], v.options.VerifyName, v.options.VerifyNameType)
	if err != nil {
		return err
	}
	err = verifyPeerFingerprint(verifiedChains, v.options.PeerFingerprints)
	if err != nil {
		return err
	}
	err = verifyRequiredKeyUsage(peerCertificates[0], v.options.RequiredKeyUsage)
	if err != nil {
		return err
	}
	if v.options.RequireKeyUsageExtension {
		err = verifyKeyUsageExtensionPresent(peerCertificates[0])
		if err != nil {
			return err
		}
	}
	err = verifyRequiredExtendedKeyUsage(peerCertificates[0], v.options.RequiredExtendedUsage)
	if err != nil {
		return err
	}
	err = verifyNSCertType(peerCertificates[0], v.options.NSCertificateType)
	if err != nil {
		return err
	}
	err = verifyAgainstCRL(verifiedChains, v.options.CRLPath)
	if err != nil {
		return err
	}
	return nil
}

// Upstream tls_ctx_set_cert_profile maps "preferred" to OpenSSL SECLEVEL 2.
func enforceCertificateProfile(verifiedChains [][]*x509.Certificate, profile string) error {
	if profile != "preferred" {
		return nil
	}
	if len(verifiedChains) == 0 {
		return nil
	}
	for _, chainCertificate := range verifiedChains[0] {
		err := enforcePreferredPublicKey(chainCertificate)
		if err != nil {
			return err
		}
		err = enforcePreferredSignatureAlgorithm(chainCertificate)
		if err != nil {
			return err
		}
	}
	return nil
}

func enforcePreferredPublicKey(peerCertificate *x509.Certificate) error {
	switch publicKey := peerCertificate.PublicKey.(type) {
	case *rsa.PublicKey:
		if publicKey.N.BitLen() < 2048 {
			return E.New("tls-cert-profile preferred rejects RSA key smaller than 2048 bits")
		}
	case *ecdsa.PublicKey:
		if publicKey.Curve.Params().BitSize < 224 {
			return E.New("tls-cert-profile preferred rejects ECDSA curve smaller than 224 bits")
		}
	}
	return nil
}

func enforcePreferredSignatureAlgorithm(peerCertificate *x509.Certificate) error {
	switch peerCertificate.SignatureAlgorithm {
	case x509.MD2WithRSA,
		x509.MD5WithRSA,
		x509.SHA1WithRSA,
		x509.DSAWithSHA1,
		x509.ECDSAWithSHA1:
		return E.New("tls-cert-profile preferred rejects legacy signature algorithm")
	}
	return nil
}

// Upstream x509_verify_cert_ku compares --remote-cert-ku against the
// OpenSSL MSB-first key usage layout.
func verifyRequiredKeyUsage(peerCertificate *x509.Certificate, requiredKeyUsage uint) error {
	if requiredKeyUsage == 0 {
		return nil
	}
	openSSLKeyUsage, present, err := reconstructOpenSSLKeyUsage(peerCertificate)
	if err != nil {
		return err
	}
	if !present {
		return ErrPeerCertificateKeyUsage
	}
	if openSSLKeyUsage&requiredKeyUsage != requiredKeyUsage {
		return ErrPeerCertificateKeyUsage
	}
	return nil
}

// Upstream x509_verify_cert_ku reads id-ce-keyUsage MSB-first and applies
// the low-byte fixup to build the OpenSSL key usage mask.
func reconstructOpenSSLKeyUsage(peerCertificate *x509.Certificate) (uint, bool, error) {
	for _, extension := range peerCertificate.Extensions {
		if !extension.Id.Equal(keyUsageExtensionOID) {
			continue
		}
		var bitString asn1.BitString
		_, err := asn1.Unmarshal(extension.Value, &bitString)
		if err != nil {
			return 0, false, err
		}
		var openSSLKeyUsage uint
		for i := range 8 {
			if bitString.At(i) == 1 {
				openSSLKeyUsage |= 1 << (7 - i)
			}
		}
		if openSSLKeyUsage&0xff == 0 {
			openSSLKeyUsage >>= 8
		}
		return openSSLKeyUsage, true, nil
	}
	return 0, false, nil
}

// Upstream x509_verify_cert_ku treats OPENVPN_KU_REQUIRED as "extension
// present, bits checked by TLS library".
func verifyKeyUsageExtensionPresent(peerCertificate *x509.Certificate) error {
	for _, extension := range peerCertificate.Extensions {
		if extension.Id.Equal(keyUsageExtensionOID) {
			return nil
		}
	}
	return ErrPeerCertificateKeyUsage
}

var keyUsageExtensionOID = asn1.ObjectIdentifier{2, 5, 29, 15}

// Upstream x509_verify_ns_cert_type still accepts Netscape Cert Type as
// a fallback to EKU.
var netscapeCertTypeExtensionOID = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1}

// Upstream x509_verify_ns_cert_type reads NS_SSL_CLIENT / NS_SSL_SERVER MSB-first.
const (
	netscapeCertTypeSSLClient = 0x80
	netscapeCertTypeSSLServer = 0x40
)

// Upstream x509_verify_ns_cert_type accepts either EKU or Netscape Cert Type.
func verifyNSCertType(peerCertificate *x509.Certificate, requirement string) error {
	if requirement == "" {
		return nil
	}
	var expectedEKU x509.ExtKeyUsage
	var expectedNetscapeBit byte
	switch requirement {
	case "server":
		expectedEKU = x509.ExtKeyUsageServerAuth
		expectedNetscapeBit = netscapeCertTypeSSLServer
	case "client":
		expectedEKU = x509.ExtKeyUsageClientAuth
		expectedNetscapeBit = netscapeCertTypeSSLClient
	default:
		return E.New("ns-cert-type must be 'server' or 'client', got: ", requirement)
	}
	if slices.Contains(peerCertificate.ExtKeyUsage, expectedEKU) {
		return nil
	}
	hasLegacyMatch, err := checkNetscapeCertTypeBit(peerCertificate, expectedNetscapeBit)
	if err != nil {
		return err
	}
	if hasLegacyMatch {
		return nil
	}
	return ErrPeerCertificateNSCertType
}

func checkNetscapeCertTypeBit(peerCertificate *x509.Certificate, expectedBit byte) (bool, error) {
	for _, extension := range peerCertificate.Extensions {
		if !extension.Id.Equal(netscapeCertTypeExtensionOID) {
			continue
		}
		var bitString asn1.BitString
		_, err := asn1.Unmarshal(extension.Value, &bitString)
		if err != nil {
			return false, err
		}
		if len(bitString.Bytes) == 0 {
			return false, nil
		}
		return bitString.Bytes[0]&expectedBit == expectedBit, nil
	}
	return false, nil
}

func verifyRequiredExtendedKeyUsage(peerCertificate *x509.Certificate, requiredExtendedUsage []x509.ExtKeyUsage) error {
	if len(requiredExtendedUsage) == 0 {
		return nil
	}
	for _, expectedExtendedUsage := range requiredExtendedUsage {
		matched := slices.Contains(peerCertificate.ExtKeyUsage, expectedExtendedUsage)
		if !matched {
			return ErrPeerCertificateExtUsage
		}
	}
	return nil
}

// Upstream tls_ctx_reload_crl applies OpenSSL CRL_CHECK | CRL_CHECK_ALL.
func verifyAgainstCRL(verifiedChains [][]*x509.Certificate, crlPath string) error {
	if crlPath == "" {
		return nil
	}
	revocationList, err := loadRevocationList(crlPath)
	if err != nil {
		return err
	}
	if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
		return ErrCRLSignatureInvalid
	}
	chain := verifiedChains[0]
	signer := findCRLSignerInChain(chain, revocationList.RawIssuer)
	if signer == nil {
		return ErrCRLSignatureInvalid
	}
	signatureErr := revocationList.CheckSignatureFrom(signer)
	if signatureErr != nil {
		return ErrCRLSignatureInvalid
	}
	now := time.Now()
	if now.Before(revocationList.ThisUpdate) {
		return ErrCRLExpired
	}
	if !revocationList.NextUpdate.IsZero() && now.After(revocationList.NextUpdate) {
		return ErrCRLExpired
	}
	for _, chainMember := range chain {
		if !bytes.Equal(chainMember.RawIssuer, revocationList.RawIssuer) {
			continue
		}
		for _, revokedEntry := range revocationList.RevokedCertificateEntries {
			if revokedEntry.SerialNumber == nil || chainMember.SerialNumber == nil {
				continue
			}
			if revokedEntry.SerialNumber.Cmp(chainMember.SerialNumber) == 0 {
				return ErrPeerCertificateRevoked
			}
		}
	}
	return nil
}

func findCRLSignerInChain(chain []*x509.Certificate, rawIssuer []byte) *x509.Certificate {
	for _, candidate := range chain {
		if bytes.Equal(candidate.RawSubject, rawIssuer) {
			return candidate
		}
	}
	return nil
}

func loadRevocationList(crlPath string) (*x509.RevocationList, error) {
	crlBytes, err := os.ReadFile(crlPath)
	if err != nil {
		return nil, err
	}
	if pemBlock, _ := pem.Decode(crlBytes); pemBlock != nil {
		crlBytes = pemBlock.Bytes
	}
	return x509.ParseRevocationList(crlBytes)
}

func parseRemoteCertKeyUsages(values []string) (uint, error) {
	if len(values) == 0 {
		return 0, nil
	}
	var combined uint
	for _, value := range values {
		if value == "" {
			return 0, E.New("empty key usage hex")
		}
		parsed, err := parseHexKeyUsage(value)
		if err != nil {
			return 0, err
		}
		combined |= parsed
	}
	return combined, nil
}

// Upstream add_option parses --remote-cert-ku with sscanf("%x").
func parseHexKeyUsage(value string) (uint, error) {
	if value == "" {
		return 0, E.New("empty key usage hex")
	}
	parsed, err := strconv.ParseUint(value, 16, strconv.IntSize)
	if err != nil {
		return 0, err
	}
	return uint(parsed), nil
}

func parseRemoteCertExtKeyUsage(value string) ([]x509.ExtKeyUsage, error) {
	if value == "" {
		return nil, nil
	}
	switch value {
	case "server":
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil
	case "client":
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil
	default:
		return nil, E.New("unsupported remote-cert-eku value: ", value)
	}
}

// Upstream add_option expands --remote-cert-tls into KU-required plus EKU.
func expandRemoteCertTLS(mode string, peerRole string) (bool, []x509.ExtKeyUsage, error) {
	if mode == "" {
		return false, nil, nil
	}
	switch mode {
	case "server":
		_ = peerRole
		return true, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil
	case "client":
		return true, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil
	default:
		return false, nil, E.New("remote-cert-tls must be 'client' or 'server', got: ", mode)
	}
}

func mergeExtendedKeyUsage(existing []x509.ExtKeyUsage, additional []x509.ExtKeyUsage) []x509.ExtKeyUsage {
	if len(additional) == 0 {
		return existing
	}
	if len(existing) == 0 {
		return additional
	}
	merged := make([]x509.ExtKeyUsage, 0, len(existing)+len(additional))
	merged = append(merged, existing...)
	for _, addition := range additional {
		if !slices.Contains(merged, addition) {
			merged = append(merged, addition)
		}
	}
	return merged
}

// Upstream --peer-fingerprint compares the leaf certificate's SHA256 digest
// against the configured hash list.
func verifyPeerFingerprint(verifiedChains [][]*x509.Certificate, expectedFingerprints []string) error {
	if len(expectedFingerprints) == 0 {
		return nil
	}
	if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
		return E.New("peer-fingerprint requires a verified certificate chain")
	}
	actualFingerprint := computeCertificateFingerprint(verifiedChains[0][0].Raw)
	if slices.Contains(expectedFingerprints, actualFingerprint) {
		return nil
	}
	return E.New("peer fingerprint mismatch")
}

func computeCertificateFingerprint(rawCertificate []byte) string {
	digest := sha256.Sum256(rawCertificate)
	return hex.EncodeToString(digest[:])
}
