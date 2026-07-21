package openvpn

import E "github.com/sagernet/sing/common/exceptions"

type allowCompressionPolicy int

const (
	allowCompressionStubOnly allowCompressionPolicy = iota
	allowCompressionAsymmetric
	// OpenVPN 2.7 maps explicit "yes" to asymmetric mode. Keep outbound
	// compression here only for explicitly requested legacy compatibility.
	allowCompressionYes
)

// Upstream options_postprocess_mutate (options.c) rejects bad
// --allow-compression tokens.
var ErrInvalidAllowCompression = E.New("invalid allow-compression value")

// Upstream options_postprocess_mutate (options.c) flags
// --allow-compression no with non-stub compression.
var ErrAllowCompressionConflict = E.New("allow-compression no conflicts with statically enabled compression")

func validateCompressionOptions(compression string, compressionLZO string) error {
	if compression != "" &&
		compression != "none" &&
		compression != "no" &&
		compression != "lz4" &&
		compression != "lz4-v2" &&
		compression != "stub" &&
		compression != "stub-v2" &&
		compression != "disabled" &&
		compression != "off" {
		return ErrCompressionNotSupported
	}
	if compressionLZO != "" &&
		compressionLZO != "none" &&
		compressionLZO != "no" &&
		compressionLZO != "yes" &&
		compressionLZO != "adaptive" &&
		compressionLZO != "asym" &&
		compressionLZO != "disabled" &&
		compressionLZO != "off" {
		return ErrCompressionNotSupported
	}
	return nil
}

func parseAllowCompressionPolicy(value string) (allowCompressionPolicy, error) {
	switch value {
	case "", "no":
		return allowCompressionStubOnly, nil
	case "asym":
		return allowCompressionAsymmetric, nil
	case "yes":
		return allowCompressionYes, nil
	}
	return 0, ErrInvalidAllowCompression
}

// Upstream comp_non_stub_enabled (comp.h) treats COMP_ALG_UNDEF,
// COMP_ALG_STUB (compress stub), and COMP_ALGV2_UNCOMPRESSED
// (compress stub-v2) as stub compression.
func compressionFramingIsStub(framingValue string, lzoValue string) bool {
	switch framingValue {
	case "lz4", "lz4-v2":
		return false
	}
	switch lzoValue {
	case "yes", "adaptive", "asym":
		return false
	}
	return true
}

func resolveEffectiveAllowCompressionPolicy(allowCompression string, compression string, compressionLZO string) (allowCompressionPolicy, error) {
	staticCompressionIsNonStub := !compressionFramingIsStub(compression, compressionLZO)
	if allowCompression == "" {
		if staticCompressionIsNonStub {
			return allowCompressionAsymmetric, nil
		}
		return allowCompressionStubOnly, nil
	}
	policy, err := parseAllowCompressionPolicy(allowCompression)
	if err != nil {
		return 0, err
	}
	if policy == allowCompressionStubOnly && staticCompressionIsNonStub {
		return 0, ErrAllowCompressionConflict
	}
	return policy, nil
}
