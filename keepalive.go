package openvpn

import "bytes"

var openVPNDataChannelPingPayload = []byte{
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
}

// Upstream occ.c uses this 16-byte OCC magic.
var openVPNOCCMagic = []byte{
	0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81,
	0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c,
}

const (
	openVPNOCCRequest byte = 0
	openVPNOCCReply   byte = 1
	openVPNOCCExit    byte = 6
)

// Upstream occ_send_exit_msg/process_received_occ_msg use OCC_EXIT.
var openVPNDataChannelExitNotifyPayload = append(append([]byte{}, openVPNOCCMagic...), openVPNOCCExit)

func occOpcode(payload []byte) int {
	if !bytes.HasPrefix(payload, openVPNOCCMagic) {
		return -1
	}
	if len(payload) < len(openVPNOCCMagic)+1 {
		return -1
	}
	return int(payload[len(openVPNOCCMagic)])
}

// Upstream process_received_occ_msg writes a trailing NUL in OCC_REPLY.
func buildOCCReplyPayload(optionsString string) []byte {
	payload := make([]byte, 0, len(openVPNOCCMagic)+1+len(optionsString)+1)
	payload = append(payload, openVPNOCCMagic...)
	payload = append(payload, openVPNOCCReply)
	payload = append(payload, []byte(optionsString)...)
	payload = append(payload, 0)
	return payload
}

// Upstream process_received_occ_msg replies only to OCC_REQUEST.
func buildOCCResponseForIncoming(incomingPayload []byte, localOptionsString string) ([]byte, bool) {
	switch occOpcode(incomingPayload) {
	case int(openVPNOCCRequest):
		if localOptionsString == "" {
			return nil, false
		}
		return buildOCCReplyPayload(localOptionsString), true
	default:
		return nil, false
	}
}
