package openvpn

import (
	"strings"
	"time"

	"github.com/sagernet/sing/common/buf"
)

type dataCodec interface {
	Encode(packetID uint32, aadPrefix []byte, payload []byte) ([]byte, error)
	EncodeBuffer(packetID uint32, aadPrefix []byte, payload *buf.Buffer) (*buf.Buffer, error)
	Decode(aadPrefix []byte, payload []byte) (uint32, []byte, error)
	DecodeBuffer(aadPrefix []byte, payload []byte, headroom int) (uint32, *buf.Buffer, error)
	EncodedLength(payloadLength int) int
}

func newTLSDataCodec(keyMaterial []byte, server bool, cipherName string, authName string, transportProtocol string, replayWindowSize uint32, replayWindowTime time.Duration) (dataCodec, error) {
	replayWindowSize, replayWindowTime = dataReplayWindowParameters(transportProtocol, replayWindowSize, replayWindowTime)
	switch cipherName {
	case "AES-128-GCM", "AES-192-GCM", "AES-256-GCM":
		return newTLSGCMDataCodec(keyMaterial, server, cipherName, replayWindowSize, replayWindowTime)
	case "CHACHA20-POLY1305":
		return newTLSChaCha20Poly1305DataCodec(keyMaterial, server, replayWindowSize, replayWindowTime)
	default:
		_, _, _, streamCipherErr := tlsStreamCipherSpec(cipherName)
		if streamCipherErr == nil {
			return newTLSStreamDataCodec(keyMaterial, server, cipherName, authName, replayWindowSize, replayWindowTime)
		}
		return newTLSCBCDataCodec(keyMaterial, server, cipherName, authName, replayWindowSize, replayWindowTime)
	}
}

func dataReplayWindowParameters(transportProtocol string, replayWindowSize uint32, replayWindowTime time.Duration) (uint32, time.Duration) {
	if strings.HasPrefix(strings.ToLower(transportProtocol), "tcp") {
		return 0, 0
	}
	if replayWindowSize == 0 {
		replayWindowSize = defaultReplayWindowSize
	}
	if replayWindowTime == 0 {
		replayWindowTime = defaultReplayWindowTime
	}
	return replayWindowSize, replayWindowTime
}

func tlsDataKeySlots(keySlots []staticKeySlot, server bool) (staticKeySlot, staticKeySlot) {
	if server {
		return keySlots[1], keySlots[0]
	}
	return keySlots[0], keySlots[1]
}
