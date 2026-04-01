package openvpn

import (
	"bytes"

	"github.com/sagernet/sing/common/buf"
)

type dataCodec interface {
	Encode(packetID uint32, aadPrefix []byte, payload []byte) ([]byte, error)
	EncodeBuffer(packetID uint32, aadPrefix []byte, payload *buf.Buffer) (*buf.Buffer, error)
	Decode(aadPrefix []byte, payload []byte) (uint32, []byte, error)
	DecodeBuffer(aadPrefix []byte, payload []byte, headroom int) (uint32, *buf.Buffer, error)
	EncodedLength(payloadLength int) int
}

type plainDataCodec struct{}

func resolveStaticCipherName(mode string, cipherName string, dataCiphers []string) string {
	if mode != ModeStaticKey {
		return cipherName
	}
	if cipherName != "" {
		return cipherName
	}
	for _, dataCipher := range dataCiphers {
		_, err := staticCipherKeySize(dataCipher)
		if err == nil {
			return dataCipher
		}
	}
	return "BF-CBC"
}

func validateDeprecatedCrypto(mode string, cipherName string, authName string) error {
	if mode != ModeStaticKey {
		return nil
	}
	switch cipherName {
	case "BF-CBC", "DES-EDE3-CBC":
		return ErrDeprecatedCryptoDisabled
	}
	if authName == "MD5" {
		return ErrDeprecatedCryptoDisabled
	}
	return nil
}

func (c *plainDataCodec) EncodedLength(payloadLength int) int {
	return payloadLength
}

func (c *plainDataCodec) Encode(packetID uint32, aadPrefix []byte, payload []byte) ([]byte, error) {
	_ = packetID
	_ = aadPrefix
	return bytes.Clone(payload), nil
}

func (c *plainDataCodec) EncodeBuffer(packetID uint32, aadPrefix []byte, payload *buf.Buffer) (*buf.Buffer, error) {
	_ = packetID
	_ = aadPrefix
	return payload, nil
}

func (c *plainDataCodec) Decode(aadPrefix []byte, payload []byte) (uint32, []byte, error) {
	_ = aadPrefix
	return 0, bytes.Clone(payload), nil
}

func (c *plainDataCodec) DecodeBuffer(aadPrefix []byte, payload []byte, headroom int) (uint32, *buf.Buffer, error) {
	_ = aadPrefix
	return 0, newDataPacketBuffer(headroom, payload), nil
}

func newDataCodec(mode string, cipherName string, authName string, staticKey Material, keyDirection int) (dataCodec, error) {
	switch mode {
	case ModeTLS:
		return &plainDataCodec{}, nil
	case ModeStaticKey:
		return newStaticKeyDataCodec(staticKey, keyDirection, cipherName, authName)
	default:
		return nil, ErrUnsupportedMode
	}
}

func newTLSDataCodec(keyMaterial []byte, server bool, cipherName string, authName string, replayWindowSize uint32) (dataCodec, error) {
	// Upstream init_options leaves the default replay-window when the option is absent.
	if replayWindowSize == 0 {
		replayWindowSize = defaultReplayWindowSize
	}
	switch cipherName {
	case "AES-128-GCM", "AES-256-GCM":
		return newTLSGCMDataCodec(keyMaterial, server, cipherName, replayWindowSize)
	case "CHACHA20-POLY1305":
		return newTLSChaCha20Poly1305DataCodec(keyMaterial, server, replayWindowSize)
	default:
		return newTLSCBCDataCodec(keyMaterial, server, cipherName, authName, replayWindowSize)
	}
}

func tlsDataKeySlots(keySlots []staticKeySlot, server bool) (staticKeySlot, staticKeySlot) {
	if server {
		return keySlots[1], keySlots[0]
	}
	return keySlots[0], keySlots[1]
}
