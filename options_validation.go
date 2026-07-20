package openvpn

import (
	"strconv"
	"strings"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

func validateMode(mode string) (string, error) {
	switch mode {
	case ModeTLS, ModeStaticKey:
		return mode, nil
	default:
		return "", ErrUnsupportedMode
	}
}

func validateImplementedClientOptions(options ClientOptions) error {
	dataChannelOptions := options.DataChannel
	tlsOptions := options.TLS
	timingOptions := options.Timing
	if options.KeyDirection < -1 || options.KeyDirection > 1 {
		return E.New("ClientOptions.KeyDirection must be -1, 0, or 1")
	}
	err := validateClientMaterialSources(options)
	if err != nil {
		return err
	}
	err = validateClientDurationOptions(options)
	if err != nil {
		return err
	}
	err = validateDataChannelNames(
		"ClientOptions.DataChannel",
		dataChannelOptions.Cipher,
		dataChannelOptions.Ciphers,
		dataChannelOptions.FallbackCipher,
		dataChannelOptions.Auth,
	)
	if err != nil {
		return err
	}
	err = validateTLSOptionNames(
		"ClientOptions.TLS",
		tlsOptions.VerifyX509Type,
		tlsOptions.PeerFingerprint,
		tlsOptions.RemoteCertificateKU,
		tlsOptions.RemoteCertificateEKU,
		tlsOptions.RemoteCertificateTLS,
		tlsOptions.NSCertificateType,
		tlsOptions.VersionMin,
		tlsOptions.VersionMax,
		tlsOptions.CertificateProfile,
		tlsOptions.Cipher,
		tlsOptions.Groups,
	)
	if err != nil {
		return err
	}
	err = validateTLSCredentialSet(
		options.Mode,
		tlsOptions.CertificateAuthority,
		tlsOptions.Certificate,
		tlsOptions.Key,
		tlsOptions.PeerFingerprint,
		false,
	)
	if err != nil {
		return err
	}
	err = validateClientPolicyOptions(options)
	if err != nil {
		return err
	}
	if options.Mode == ModeTLS && options.StaticKey.IsSet() {
		return E.Extend(ErrOptionNotSupported, "static_key in tls mode")
	}
	if options.Mode == ModeStaticKey && hasTLSCredentialMaterial(
		tlsOptions.CertificateAuthority,
		tlsOptions.Certificate,
		tlsOptions.Key,
		tlsOptions.Auth,
		tlsOptions.Crypt,
		tlsOptions.CryptV2,
	) {
		return E.Extend(ErrOptionNotSupported, "TLS material in static_key mode")
	}
	if options.Mode == ModeStaticKey && (tlsOptions.VerifyX509Name != "" || tlsOptions.VerifyX509Type != "" ||
		len(tlsOptions.PeerFingerprint) > 0 || tlsOptions.CRLVerify != "" || len(tlsOptions.RemoteCertificateKU) > 0 ||
		tlsOptions.RemoteCertificateEKU != "" || tlsOptions.RemoteCertificateTLS != "" || tlsOptions.NSCertificateType != "" ||
		tlsOptions.VersionMin != "" || tlsOptions.VersionMax != "" || tlsOptions.CertificateProfile != "" ||
		tlsOptions.Cipher != "" || tlsOptions.Groups != "" ||
		timingOptions.TLSTimeout != 0 || timingOptions.HandWindow != 0 || timingOptions.RenegotiationBytes != 0 ||
		timingOptions.RenegotiationPackets != 0) {
		return E.Extend(ErrOptionNotSupported, "TLS options in static_key mode")
	}
	tlsAuthSet := tlsOptions.Auth.IsSet()
	tlsCryptSet := tlsOptions.Crypt.IsSet()
	tlsCryptV2Set := tlsOptions.CryptV2.IsSet()
	if tlsAuthSet && tlsCryptSet {
		return E.Extend(ErrOptionNotSupported, "tls_auth+tls_crypt")
	}
	if tlsAuthSet && tlsCryptV2Set {
		return E.Extend(ErrOptionNotSupported, "tls_auth+tls_crypt_v2")
	}
	if tlsCryptSet && tlsCryptV2Set {
		return E.Extend(ErrOptionNotSupported, "tls_crypt+tls_crypt_v2")
	}
	return nil
}

func validateClientPolicyOptions(options ClientOptions) error {
	if options.Tunnel.DevType != "" && options.Tunnel.DevType != "tun" {
		return E.New("ClientOptions.Tunnel.DevType must be tun")
	}
	switch options.Tunnel.Topology {
	case "", "net30", "p2p", "subnet":
	default:
		return E.New("ClientOptions.Tunnel.Topology must be net30, p2p, or subnet")
	}
	switch options.Authentication.AuthRetry {
	case "", "none", "nointeract", "interact":
	default:
		return E.New("ClientOptions.Authentication.AuthRetry must be none, nointeract, or interact")
	}
	for filterIndex, filter := range options.Pull.Filters {
		switch filter.Action {
		case "accept", "ignore", "reject":
		default:
			return E.New("ClientOptions.Pull.Filters[", filterIndex, "].Action must be accept, ignore, or reject")
		}
		if filter.Text == "" {
			return E.New("ClientOptions.Pull.Filters[", filterIndex, "].Text must not be empty")
		}
	}
	if options.DataChannel.Fragment > 0 && options.DataChannel.Fragment < 68 {
		return E.New("ClientOptions.DataChannel.Fragment must be zero or at least 68")
	}
	return nil
}

func validateDataChannelNames(optionsName string, cipherName string, dataCiphers []string, fallbackCipher string, authName string) error {
	err := validateDataCipherName(optionsName+".Cipher", cipherName)
	if err != nil {
		return err
	}
	for cipherIndex, dataCipher := range dataCiphers {
		if dataCipher == "" {
			return E.New(optionsName, ".Ciphers[", cipherIndex, "] must not be empty")
		}
		err = validateDataCipherName(optionsName+".Ciphers["+strconv.Itoa(cipherIndex)+"]", dataCipher)
		if err != nil {
			return err
		}
	}
	err = validateDataCipherName(optionsName+".FallbackCipher", fallbackCipher)
	if err != nil {
		return err
	}
	switch authName {
	case "", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "RIPEMD160", "MD5", "NONE":
		return nil
	default:
		return E.New(optionsName, ".Auth must use a canonical OpenVPN digest name")
	}
}

func validateDataCipherName(name string, cipherName string) error {
	switch cipherName {
	case "", "BF-CBC", "DES-EDE3-CBC", "AES-128-CBC", "AES-192-CBC", "AES-256-CBC",
		"AES-128-GCM", "AES-256-GCM", "CHACHA20-POLY1305", "NONE":
		return nil
	default:
		return E.New(name, " must use a canonical OpenVPN cipher name")
	}
}

func validateTLSOptionNames(optionsName string, verifyX509Type string, peerFingerprints []string, remoteCertKU []string, remoteCertEKU string, remoteCertTLS string, nsCertType string, versionMin string, versionMax string, certProfile string, tlsCipher string, tlsGroups string) error {
	switch verifyX509Type {
	case "", "subject", "name", "name-prefix":
	default:
		return E.New(optionsName, ".VerifyX509Type must be subject, name, or name-prefix")
	}
	for fingerprintIndex, fingerprint := range peerFingerprints {
		if len(fingerprint) != 64 || !isLowerHex(fingerprint) {
			return E.New(optionsName, ".PeerFingerprint[", fingerprintIndex, "] must be canonical lowercase hex")
		}
	}
	_, err := parseRemoteCertKeyUsages(remoteCertKU)
	if err != nil {
		return err
	}
	_, err = parseRemoteCertExtKeyUsage(remoteCertEKU)
	if err != nil {
		return err
	}
	_, _, err = expandRemoteCertTLS(remoteCertTLS, "")
	if err != nil {
		return err
	}
	switch nsCertType {
	case "", "server", "client":
	default:
		return E.New(optionsName, ".NSCertificateType must be server or client")
	}
	_, _, err = resolveTLSVersionBounds(versionMin, versionMax)
	if err != nil {
		return err
	}
	_, err = parseTLSCertProfile(certProfile)
	if err != nil {
		return err
	}
	_, err = parseTLSCipherSuites(tlsCipher)
	if err != nil {
		return err
	}
	_, err = parseTLSGroups(tlsGroups)
	return err
}

func isLowerHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validateImplementedServerOptions(options ServerOptions) error {
	dataChannelOptions := options.DataChannel
	tlsOptions := options.TLS
	if options.KeyDirection < -1 || options.KeyDirection > 1 {
		return E.New("ServerOptions.KeyDirection must be -1, 0, or 1")
	}
	err := validateServerMaterialSources(options)
	if err != nil {
		return err
	}
	err = validateServerDurationOptions(options)
	if err != nil {
		return err
	}
	err = validateDataChannelNames(
		"ServerOptions.DataChannel",
		"",
		dataChannelOptions.Ciphers,
		dataChannelOptions.FallbackCipher,
		dataChannelOptions.Auth,
	)
	if err != nil {
		return err
	}
	err = validateTLSCredentialSet(
		options.Mode,
		tlsOptions.CertificateAuthority,
		tlsOptions.Certificate,
		tlsOptions.Key,
		nil,
		true,
	)
	if err != nil {
		return err
	}
	_, err = parseTLSCertProfile(tlsOptions.CertificateProfile)
	if err != nil {
		return err
	}
	err = validateServerTransportOptions(options)
	if err != nil {
		return err
	}
	err = validateServerResourceOptions(options)
	if err != nil {
		return err
	}
	err = validateServerTunnelOptions(options)
	if err != nil {
		return err
	}
	tlsAuthSet := tlsOptions.Auth.IsSet()
	tlsCryptSet := tlsOptions.Crypt.IsSet()
	tlsCryptV2Set := tlsOptions.CryptV2.IsSet()
	if tlsOptions.CryptV2ForceCookie && !tlsCryptV2Set {
		return E.New("ServerOptions.TLS.CryptV2ForceCookie requires tls-crypt-v2")
	}
	if tlsAuthSet && tlsCryptSet {
		return E.Extend(ErrOptionNotSupported, "tls_auth+tls_crypt")
	}
	if tlsAuthSet && tlsCryptV2Set {
		return E.Extend(ErrOptionNotSupported, "tls_auth+tls_crypt_v2")
	}
	if tlsCryptSet && tlsCryptV2Set {
		return E.Extend(ErrOptionNotSupported, "tls_crypt+tls_crypt_v2")
	}
	return nil
}

func validateServerResourceOptions(options ServerOptions) error {
	resourceOptions := options.Resources
	if resourceOptions.MaxClients < 0 {
		return E.New("ServerOptions.Resources.MaxClients must not be negative")
	}
	if resourceOptions.MaxClients >= 1<<24 {
		return E.New("ServerOptions.Resources.MaxClients must fit in the 24-bit OpenVPN peer-id space")
	}
	return nil
}

func validateClientDurationOptions(options ClientOptions) error {
	timingOptions := options.Timing
	err := validateDurationOption("ClientOptions.Timing.RenegotiationInterval", timingOptions.RenegotiationInterval)
	if err != nil {
		return err
	}
	err = validatePingDurationOption("ClientOptions.Timing.PingInterval", timingOptions.PingInterval)
	if err != nil {
		return err
	}
	err = validatePingDurationOption("ClientOptions.Timing.PingRestart", timingOptions.PingRestart)
	if err != nil {
		return err
	}
	err = validateDurationOption("ClientOptions.Timing.TLSTimeout", timingOptions.TLSTimeout)
	if err != nil {
		return err
	}
	return validateDurationOption("ClientOptions.Timing.HandWindow", timingOptions.HandWindow)
}

func validateServerDurationOptions(options ServerOptions) error {
	timingOptions := options.Timing
	err := validateDurationOption("ServerOptions.Timing.RenegotiationInterval", timingOptions.RenegotiationInterval)
	if err != nil {
		return err
	}
	err = validateDurationOption("ServerOptions.Timing.HandWindow", timingOptions.HandWindow)
	if err != nil {
		return err
	}
	err = validatePingDurationOption("ServerOptions.Timing.PingInterval", timingOptions.PingInterval)
	if err != nil {
		return err
	}
	err = validatePingDurationOption("ServerOptions.Timing.PingRestart", timingOptions.PingRestart)
	if err != nil {
		return err
	}
	err = validatePingDurationOption("ServerOptions.Push.PingInterval", options.Push.PingInterval)
	if err != nil {
		return err
	}
	return validatePingDurationOption("ServerOptions.Push.PingRestart", options.Push.PingRestart)
}

func validatePingDurationOption(name string, value time.Duration) error {
	err := validateDurationOption(name, value)
	if err != nil {
		return err
	}
	if value%time.Second != 0 {
		return E.New(name, " must use whole seconds")
	}
	return nil
}

func validateDurationOption(name string, value time.Duration) error {
	if value < 0 {
		return E.New(name, " must not be negative")
	}
	if value > 0 && value < time.Second {
		return E.New(name, " must be zero or at least 1s")
	}
	return nil
}

func validateServerTunnelOptions(options ServerOptions) error {
	switch options.Tunnel.Topology {
	case "", "net30", "p2p", "subnet":
	default:
		return E.New("ServerOptions.Tunnel.Topology must be net30, p2p, or subnet")
	}
	return nil
}

func validateClientMaterialSources(options ClientOptions) error {
	for _, source := range []struct {
		name     string
		material Material
	}{
		{"certificate-authority", options.TLS.CertificateAuthority},
		{"certificate", options.TLS.Certificate},
		{"key", options.TLS.Key},
		{"tls-auth", options.TLS.Auth},
		{"tls-crypt", options.TLS.Crypt},
		{"tls-crypt-v2", options.TLS.CryptV2},
		{"static-key", options.StaticKey},
	} {
		err := source.material.Validate(source.name)
		if err != nil {
			return err
		}
	}
	return nil
}

func validateServerMaterialSources(options ServerOptions) error {
	for _, source := range []struct {
		name     string
		material Material
	}{
		{"certificate-authority", options.TLS.CertificateAuthority},
		{"certificate", options.TLS.Certificate},
		{"key", options.TLS.Key},
		{"tls-auth", options.TLS.Auth},
		{"tls-crypt", options.TLS.Crypt},
		{"tls-crypt-v2", options.TLS.CryptV2},
	} {
		err := source.material.Validate(source.name)
		if err != nil {
			return err
		}
	}
	return nil
}

func resolveTransportProtocol(protocol string) (string, string, error) {
	switch protocol {
	case "udp":
		return protocol, "udp", nil
	case "udp4":
		return protocol, "udp4", nil
	case "udp6":
		return protocol, "udp6", nil
	case "tcp":
		return protocol, "tcp", nil
	case "tcp4":
		return protocol, "tcp4", nil
	case "tcp6":
		return protocol, "tcp6", nil
	}
	return "", "", ErrUnsupportedProtocol
}

func validateServerTransportOptions(options ServerOptions) error {
	if strings.ContainsAny(options.Transport.ListenAddress, " \t\r\n") {
		return E.New("ServerOptions.Transport.ListenAddress must not contain whitespace")
	}
	injectedCount := 0
	if options.Transport.Listener != nil {
		injectedCount++
	}
	if options.Transport.PacketConn != nil {
		injectedCount++
	}
	if injectedCount > 1 {
		return E.Extend(ErrOptionNotSupported, "multiple server transports")
	}
	if strings.HasPrefix(options.Transport.Protocol, "tcp") {
		if options.Transport.PacketConn != nil {
			return E.Extend(ErrOptionNotSupported, "packet transport in tcp mode")
		}
		return nil
	}
	if options.Transport.Listener != nil {
		return E.Extend(ErrOptionNotSupported, "stream transport in udp mode")
	}
	return nil
}
