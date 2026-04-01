package openvpn

import (
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// Upstream options_string_extract_option (ssl.c) translates the legacy
// "[null-cipher]" sentinel to "none".
func extractRemoteCipherName(optionsString string) string {
	for rawToken := range strings.SplitSeq(optionsString, ",") {
		trimmedToken := strings.TrimSpace(rawToken)
		const prefix = "cipher "
		if !strings.HasPrefix(trimmedToken, prefix) {
			continue
		}
		cipherValue := strings.TrimSpace(trimmedToken[len(prefix):])
		if cipherValue == "[null-cipher]" {
			return "none"
		}
		return cipherValue
	}
	return ""
}

// Upstream check_pull_client_ncp/tls_poor_mans_ncp (ssl_ncp.c) uses
// data-ciphers-fallback only when the peer OptionsString has no cipher.
func applyCipherNegotiationFallback(options ClientOptions, remoteCipherName string) (string, error) {
	trimmedRemote := strings.TrimSpace(remoteCipherName)
	advertisedCiphers := tlsAdvertisedDataCiphers(options.DataChannel.Ciphers)
	if trimmedRemote != "" {
		for _, candidate := range advertisedCiphers {
			if strings.EqualFold(candidate, trimmedRemote) {
				return candidate, nil
			}
		}
		return "", E.Extend(
			ErrCipherNegotiationFailed,
			"peer cipher ", trimmedRemote,
			" not in data-ciphers ", strings.Join(advertisedCiphers, ":"),
			"; add it to --data-ciphers or reconfigure the server",
		)
	}
	if options.DataChannel.FallbackCipher != "" {
		return options.DataChannel.FallbackCipher, nil
	}
	return tlsPreferredCipher(options), nil
}

func selectP2PCipher(options ClientOptions, peerInfo string, remoteCipherName string) (string, error) {
	peerCiphers, peerCipherListKnown := parsePeerInfoCipherList(peerInfo)
	if !peerCipherListKnown {
		return applyCipherNegotiationFallback(options, remoteCipherName)
	}
	localCiphers := tlsAdvertisedDataCiphers(options.DataChannel.Ciphers)
	for _, peerCipher := range peerCiphers {
		for _, localCipher := range localCiphers {
			if strings.EqualFold(strings.TrimSpace(peerCipher), localCipher) {
				return localCipher, nil
			}
		}
	}
	if options.DataChannel.FallbackCipher != "" {
		return options.DataChannel.FallbackCipher, nil
	}
	return "", E.Extend(ErrCipherNegotiationFailed, "no shared p2p cipher")
}
