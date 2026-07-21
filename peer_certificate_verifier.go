package openvpn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"

	ctx509 "github.com/google/certificate-transparency-go/x509"
)

type peerCertificateVerifierOptions struct {
	Roots                    *certificatePool
	KeyUsage                 x509.ExtKeyUsage
	VerifyName               string
	VerifyNameType           string
	PeerFingerprints         []string
	CRLPath                  string
	RequiredKeyUsage         []uint
	RequireKeyUsageExtension bool
	RequiredExtendedUsage    []asn1.ObjectIdentifier
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
		var err error
		switch v.options.CertificateProfile {
		case "insecure":
			verifiedChains, err = verifyInsecureCertificateChain(rawCertificates, v.options.Roots, v.options.KeyUsage)
		case "legacy":
			verifiedChains, err = verifyLegacyCertificateChain(rawCertificates, v.options.Roots, v.options.KeyUsage)
		default:
			intermediates := x509.NewCertPool()
			for _, peerCertificate := range peerCertificates[1:] {
				intermediates.AddCert(peerCertificate)
			}
			verifyOptions := x509.VerifyOptions{
				Roots:         v.options.Roots.standard,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{v.options.KeyUsage},
			}
			verifiedChains, err = peerCertificates[0].Verify(verifyOptions)
		}
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

var insecureCertificateValidationKey struct {
	once sync.Once
	key  *rsa.PrivateKey
	err  error
}

func verifyInsecureCertificateChain(rawCertificates [][]byte, roots *certificatePool, keyUsage x509.ExtKeyUsage) ([][]*x509.Certificate, error) {
	peerCertificates := make([]*x509.Certificate, 0, len(rawCertificates))
	for _, rawCertificate := range rawCertificates {
		peerCertificate, err := x509.ParseCertificate(rawCertificate)
		if err != nil {
			return nil, err
		}
		peerCertificates = append(peerCertificates, peerCertificate)
	}
	insecureCertificateValidationKey.once.Do(func() {
		insecureCertificateValidationKey.key, insecureCertificateValidationKey.err = rsa.GenerateKey(rand.Reader, 2048)
	})
	if insecureCertificateValidationKey.err != nil {
		return nil, insecureCertificateValidationKey.err
	}
	validationKey := insecureCertificateValidationKey.key
	originalBySynthetic := make(map[*x509.Certificate]*x509.Certificate, len(peerCertificates)+len(roots.certificates))
	cloneCertificate := func(original *x509.Certificate) (*x509.Certificate, error) {
		cloned := *original
		cloned.PublicKeyAlgorithm = x509.RSA
		cloned.PublicKey = &validationKey.PublicKey
		cloned.SignatureAlgorithm = x509.SHA256WithRSA
		digest := sha256.Sum256(cloned.RawTBSCertificate)
		signature, err := rsa.SignPKCS1v15(nil, validationKey, crypto.SHA256, digest[:])
		if err != nil {
			return nil, err
		}
		cloned.Signature = signature
		syntheticCertificate := &cloned
		originalBySynthetic[syntheticCertificate] = original
		return syntheticCertificate, nil
	}
	syntheticPeerCertificates := make([]*x509.Certificate, 0, len(peerCertificates))
	for _, peerCertificate := range peerCertificates {
		syntheticCertificate, err := cloneCertificate(peerCertificate)
		if err != nil {
			return nil, err
		}
		syntheticPeerCertificates = append(syntheticPeerCertificates, syntheticCertificate)
	}
	syntheticIntermediates := x509.NewCertPool()
	for _, intermediate := range syntheticPeerCertificates[1:] {
		syntheticIntermediates.AddCert(intermediate)
	}
	syntheticRoots := x509.NewCertPool()
	for _, root := range roots.certificates {
		syntheticRoot, err := cloneCertificate(root)
		if err != nil {
			return nil, err
		}
		syntheticRoots.AddCert(syntheticRoot)
	}
	syntheticChains, err := syntheticPeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         syntheticRoots,
		Intermediates: syntheticIntermediates,
		KeyUsages:     []x509.ExtKeyUsage{keyUsage},
	})
	if err != nil {
		return nil, err
	}
	verifiedChains := make([][]*x509.Certificate, 0, len(syntheticChains))
	var signatureErr error
	for _, syntheticChain := range syntheticChains {
		chain := make([]*x509.Certificate, 0, len(syntheticChain))
		for _, syntheticCertificate := range syntheticChain {
			originalCertificate := originalBySynthetic[syntheticCertificate]
			if originalCertificate == nil {
				return nil, E.New("unmapped certificate in verified chain")
			}
			chain = append(chain, originalCertificate)
		}
		validSignatures := true
		for certificateIndex := 0; certificateIndex+1 < len(chain); certificateIndex++ {
			signatureErr = verifyInsecureCertificateSignature(chain[certificateIndex], chain[certificateIndex+1])
			if signatureErr != nil {
				validSignatures = false
				break
			}
		}
		if validSignatures {
			verifiedChains = append(verifiedChains, chain)
		}
	}
	if len(verifiedChains) == 0 {
		return nil, signatureErr
	}
	return verifiedChains, nil
}

func verifyInsecureCertificateSignature(certificate *x509.Certificate, parent *x509.Certificate) error {
	if certificate.SignatureAlgorithm == x509.MD5WithRSA {
		parentPublicKey, loaded := parent.PublicKey.(*rsa.PublicKey)
		if !loaded {
			return x509.ErrUnsupportedAlgorithm
		}
		digest := md5.Sum(certificate.RawTBSCertificate)
		return rsa.VerifyPKCS1v15(parentPublicKey, crypto.MD5, digest[:], certificate.Signature)
	}
	legacyCertificate, err := ctx509.ParseCertificate(certificate.Raw)
	if err != nil {
		return err
	}
	legacyParent, err := ctx509.ParseCertificate(parent.Raw)
	if err != nil {
		return err
	}
	return legacyCertificate.CheckSignatureFrom(legacyParent)
}

func enforceCertificateProfile(verifiedChains [][]*x509.Certificate, profile string) error {
	if len(verifiedChains) == 0 {
		return nil
	}
	if profile == "" {
		profile = "legacy"
	}
	for _, chainCertificate := range verifiedChains[0] {
		err := enforceCertificateProfilePublicKey(chainCertificate, profile)
		if err != nil {
			return err
		}
		err = enforceCertificateProfileSignatureAlgorithm(chainCertificate, profile)
		if err != nil {
			return err
		}
	}
	return nil
}

func enforceCertificateProfilePublicKey(peerCertificate *x509.Certificate, profile string) error {
	if profile == "insecure" {
		return nil
	}
	if profile == "suiteb" {
		publicKey, loaded := peerCertificate.PublicKey.(*ecdsa.PublicKey)
		if !loaded {
			return E.New("tls-cert-profile suiteb requires ECDSA certificates")
		}
		curveBits := publicKey.Curve.Params().BitSize
		if curveBits != 256 && curveBits != 384 {
			return E.New("tls-cert-profile suiteb requires ECDSA P-256 or P-384")
		}
		return nil
	}
	switch publicKey := peerCertificate.PublicKey.(type) {
	case *rsa.PublicKey:
		minimumBits := 1024
		if profile == "preferred" {
			minimumBits = 2048
		}
		if publicKey.N.BitLen() < minimumBits {
			return E.New("tls-cert-profile ", profile, " rejects RSA key smaller than ", minimumBits, " bits")
		}
	}
	return nil
}

func enforceCertificateProfileSignatureAlgorithm(peerCertificate *x509.Certificate, profile string) error {
	if profile == "insecure" {
		return nil
	}
	signatureAlgorithm := peerCertificate.SignatureAlgorithm
	if profile == "suiteb" {
		if signatureAlgorithm != x509.ECDSAWithSHA256 && signatureAlgorithm != x509.ECDSAWithSHA384 {
			return E.New("tls-cert-profile suiteb requires ECDSA with SHA-256 or SHA-384")
		}
		return nil
	}
	switch signatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA:
		return E.New("tls-cert-profile ", profile, " rejects insecure signature algorithm")
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		if profile == "preferred" {
			return E.New("tls-cert-profile preferred rejects SHA-1 signature algorithm")
		}
	}
	return nil
}

func verifyLegacyCertificateChain(rawCertificates [][]byte, roots *certificatePool, keyUsage x509.ExtKeyUsage) ([][]*x509.Certificate, error) {
	peerCertificate, err := ctx509.ParseCertificate(rawCertificates[0])
	if err != nil {
		return nil, err
	}
	intermediates := ctx509.NewCertPool()
	for _, rawCertificate := range rawCertificates[1:] {
		intermediate, parseErr := ctx509.ParseCertificate(rawCertificate)
		if parseErr != nil {
			return nil, parseErr
		}
		intermediates.AddCert(intermediate)
	}
	verifyOptions := ctx509.VerifyOptions{
		Roots:         roots.legacy,
		Intermediates: intermediates,
		KeyUsages:     []ctx509.ExtKeyUsage{legacyExtKeyUsage(keyUsage)},
	}
	legacyChains, err := peerCertificate.Verify(verifyOptions)
	if err != nil {
		return nil, err
	}
	verifiedChains := make([][]*x509.Certificate, 0, len(legacyChains))
	for _, legacyChain := range legacyChains {
		verifiedChain := make([]*x509.Certificate, 0, len(legacyChain))
		for _, legacyCertificate := range legacyChain {
			certificate, parseErr := x509.ParseCertificate(legacyCertificate.Raw)
			if parseErr != nil {
				return nil, parseErr
			}
			verifiedChain = append(verifiedChain, certificate)
		}
		verifiedChains = append(verifiedChains, verifiedChain)
	}
	return verifiedChains, nil
}

func legacyExtKeyUsage(keyUsage x509.ExtKeyUsage) ctx509.ExtKeyUsage {
	switch keyUsage {
	case x509.ExtKeyUsageServerAuth:
		return ctx509.ExtKeyUsageServerAuth
	case x509.ExtKeyUsageClientAuth:
		return ctx509.ExtKeyUsageClientAuth
	default:
		return ctx509.ExtKeyUsageAny
	}
}

// Upstream x509_verify_cert_ku compares --remote-cert-ku against the
// OpenSSL MSB-first key usage layout.
func verifyRequiredKeyUsage(peerCertificate *x509.Certificate, requiredKeyUsage []uint) error {
	if len(requiredKeyUsage) == 0 || requiredKeyUsage[0] == 0 {
		return nil
	}
	openSSLKeyUsage, present, err := reconstructOpenSSLKeyUsage(peerCertificate)
	if err != nil {
		return err
	}
	if !present {
		return ErrPeerCertificateKeyUsage
	}
	for _, candidateKeyUsage := range requiredKeyUsage {
		if candidateKeyUsage != 0 && openSSLKeyUsage&candidateKeyUsage == candidateKeyUsage {
			return nil
		}
	}
	return ErrPeerCertificateKeyUsage
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

func verifyRequiredExtendedKeyUsage(peerCertificate *x509.Certificate, requiredExtendedUsage []asn1.ObjectIdentifier) error {
	if len(requiredExtendedUsage) == 0 {
		return nil
	}
	certificateExtendedUsage, err := readCertificateExtendedKeyUsage(peerCertificate)
	if err != nil {
		return err
	}
	for _, expectedExtendedUsage := range requiredExtendedUsage {
		matched := slices.ContainsFunc(certificateExtendedUsage, expectedExtendedUsage.Equal)
		if !matched {
			return ErrPeerCertificateExtUsage
		}
	}
	return nil
}

var extendedKeyUsageExtensionOID = asn1.ObjectIdentifier{2, 5, 29, 37}

func readCertificateExtendedKeyUsage(peerCertificate *x509.Certificate) ([]asn1.ObjectIdentifier, error) {
	for _, extension := range peerCertificate.Extensions {
		if !extension.Id.Equal(extendedKeyUsageExtensionOID) {
			continue
		}
		var usages []asn1.ObjectIdentifier
		_, err := asn1.Unmarshal(extension.Value, &usages)
		return usages, err
	}
	return nil, nil
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

func parseRemoteCertKeyUsages(values []string) ([]uint, error) {
	if len(values) == 0 {
		return nil, nil
	}
	parsedValues := make([]uint, 0, len(values))
	for _, value := range values {
		if value == "" {
			return nil, E.New("empty key usage hex")
		}
		parsed, err := parseHexKeyUsage(value)
		if err != nil {
			return nil, err
		}
		parsedValues = append(parsedValues, parsed)
	}
	return parsedValues, nil
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

func parseRemoteCertExtKeyUsage(value string) ([]asn1.ObjectIdentifier, error) {
	if value == "" {
		return nil, nil
	}
	if knownUsage, loaded := openSSLKeyPurposeNames[value]; loaded {
		return []asn1.ObjectIdentifier{knownUsage}, nil
	}
	usage, err := parseObjectIdentifier(value)
	if err != nil {
		return nil, E.New("unsupported remote-cert-eku value: ", value)
	}
	return []asn1.ObjectIdentifier{usage}, nil
}

// Upstream add_option expands --remote-cert-tls into KU-required plus EKU.
func expandRemoteCertTLS(mode string, peerRole string) (bool, []asn1.ObjectIdentifier, error) {
	if mode == "" {
		return false, nil, nil
	}
	switch mode {
	case "server":
		_ = peerRole
		return true, []asn1.ObjectIdentifier{serverAuthOID}, nil
	case "client":
		return true, []asn1.ObjectIdentifier{clientAuthOID}, nil
	default:
		return false, nil, E.New("remote-cert-tls must be 'client' or 'server', got: ", mode)
	}
}

func mergeExtendedKeyUsage(existing []asn1.ObjectIdentifier, additional []asn1.ObjectIdentifier) []asn1.ObjectIdentifier {
	if len(additional) == 0 {
		return existing
	}
	if len(existing) == 0 {
		return additional
	}
	merged := make([]asn1.ObjectIdentifier, 0, len(existing)+len(additional))
	merged = append(merged, existing...)
	for _, addition := range additional {
		if !slices.ContainsFunc(merged, addition.Equal) {
			merged = append(merged, addition)
		}
	}
	return merged
}

func resolveVerificationExtKeyUsage(requiredUsage []asn1.ObjectIdentifier, defaultUsage x509.ExtKeyUsage) x509.ExtKeyUsage {
	if len(requiredUsage) != 1 {
		return defaultUsage
	}
	if requiredUsage[0].Equal(serverAuthOID) {
		return x509.ExtKeyUsageServerAuth
	}
	if requiredUsage[0].Equal(clientAuthOID) {
		return x509.ExtKeyUsageClientAuth
	}
	return x509.ExtKeyUsageAny
}

var (
	serverAuthOID          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	clientAuthOID          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	openSSLKeyPurposeNames = map[string]asn1.ObjectIdentifier{
		"server":                            serverAuthOID,
		"client":                            clientAuthOID,
		"TLS Web Server Authentication":     serverAuthOID,
		"TLS Web Client Authentication":     clientAuthOID,
		"Code Signing":                      {1, 3, 6, 1, 5, 5, 7, 3, 3},
		"E-mail Protection":                 {1, 3, 6, 1, 5, 5, 7, 3, 4},
		"IPSec End System":                  {1, 3, 6, 1, 5, 5, 7, 3, 5},
		"IPSec Tunnel":                      {1, 3, 6, 1, 5, 5, 7, 3, 6},
		"IPSec User":                        {1, 3, 6, 1, 5, 5, 7, 3, 7},
		"Time Stamping":                     {1, 3, 6, 1, 5, 5, 7, 3, 8},
		"OCSP Signing":                      {1, 3, 6, 1, 5, 5, 7, 3, 9},
		"Any Extended Key Usage":            {2, 5, 29, 37, 0},
		"Microsoft Server Gated Crypto":     {1, 3, 6, 1, 4, 1, 311, 10, 3, 3},
		"Netscape Server Gated Crypto":      {2, 16, 840, 1, 113730, 4, 1},
		"Microsoft Commercial Code Signing": {1, 3, 6, 1, 4, 1, 311, 2, 1, 22},
		"Microsoft Individual Code Signing": {1, 3, 6, 1, 4, 1, 311, 2, 1, 21},
	}
)

func parseObjectIdentifier(value string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return nil, E.New("invalid object identifier")
	}
	identifier := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, E.New("invalid object identifier")
		}
		component, err := strconv.Atoi(part)
		if err != nil || component < 0 {
			return nil, E.New("invalid object identifier")
		}
		identifier = append(identifier, component)
	}
	if identifier[0] > 2 || identifier[0] < 2 && identifier[1] > 39 {
		return nil, E.New("invalid object identifier")
	}
	return identifier, nil
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
