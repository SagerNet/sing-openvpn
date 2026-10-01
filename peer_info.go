package openvpn

import (
	"crypto/rand"
	"fmt"
	"net"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// OpenVPN documents IV_HWADDR as an ASCII identity of at most 64 bytes when
// --push-peer-info is enabled. Keep UV_UUID under the same limit for safety.
const maxPushPeerInfoIdentityLength = 64

func preparePushPeerInfoIdentities(options *ClientOptions) error {
	if options == nil || !options.PushPeerInfo {
		return nil
	}
	if strings.TrimSpace(options.PeerUUID) == "" {
		peerUUID, err := generatePeerUUID()
		if err != nil {
			return err
		}
		options.PeerUUID = peerUUID
	}
	options.PeerUUID = strings.TrimSpace(options.PeerUUID)
	if err := validatePushPeerInfoIdentity("ClientOptions.PeerUUID", options.PeerUUID); err != nil {
		return err
	}
	if strings.TrimSpace(options.HardwareAddress) == "" {
		options.HardwareAddress = detectDefaultHardwareAddress()
	}
	options.HardwareAddress = strings.TrimSpace(options.HardwareAddress)
	if options.HardwareAddress == "" {
		return nil
	}
	return validatePushPeerInfoIdentity("ClientOptions.HardwareAddress", options.HardwareAddress)
}

func validatePushPeerInfoIdentity(fieldName string, value string) error {
	if value == "" {
		return E.New(fieldName, " must not be empty when PushPeerInfo is enabled")
	}
	if len(value) > maxPushPeerInfoIdentityLength {
		return E.New(fieldName, " must be at most ", maxPushPeerInfoIdentityLength, " bytes")
	}
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			return E.New(fieldName, " must be printable ASCII")
		}
	}
	return nil
}

func generatePeerUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", E.Cause(err, "generate peer UUID")
	}
	// RFC 4122 version 4 / variant 1.
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	// Uppercase matches OpenVPN Connect's UV_UUID presentation.
	return fmt.Sprintf(
		"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		raw[0], raw[1], raw[2], raw[3],
		raw[4], raw[5],
		raw[6], raw[7],
		raw[8], raw[9],
		raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
	), nil
}

func detectDefaultHardwareAddress() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		hardwareAddress := iface.HardwareAddr.String()
		if hardwareAddress == "" || hardwareAddress == "00:00:00:00:00:00" {
			continue
		}
		return hardwareAddress
	}
	return ""
}

func appendPushPeerInfoIdentities(builder *strings.Builder, options ClientOptions) {
	if !options.PushPeerInfo {
		return
	}
	// OpenVPN Connect advertises UV_UUID as a persistent device identity.
	// Community OpenVPN with --push-peer-info advertises IV_HWADDR for the same
	// purpose. Emit both when available so servers that require either field
	// (common with push-peer-info / device-bound auth) accept the handshake.
	if options.PeerUUID != "" {
		builder.WriteString("UV_UUID=")
		builder.WriteString(options.PeerUUID)
		builder.WriteString("\n")
	}
	if options.HardwareAddress != "" {
		builder.WriteString("IV_HWADDR=")
		builder.WriteString(options.HardwareAddress)
		builder.WriteString("\n")
	}
}
