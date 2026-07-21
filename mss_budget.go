package openvpn

import (
	"net"
	"strings"

	M "github.com/sagernet/sing/common/metadata"
)

func calculateMaximumSegmentSize(mssFix uint32, mssFixMode string, dataFraming *dataChannelFraming, codec dataCodec, packetHeaderSize int, outerTransportOverhead int) (uint16, error) {
	if mssFix == 0 {
		return 0, nil
	}
	if mssFixMode == MSSFixModeFixed {
		return uint16(min(mssFix-ipv4HeaderMinLength-tcpHeaderMinLength, 1<<16-1)), nil
	}
	if mssFixMode == MSSFixModeMTU {
		packetHeaderSize += outerTransportOverhead
	}
	maximumSegmentSize, err := calculateDataPayloadSize(
		int(mssFix),
		codec,
		packetHeaderSize,
		ipv4HeaderMinLength+tcpHeaderMinLength+dataFraming.payloadOverhead(),
	)
	if err != nil {
		return 0, err
	}
	return uint16(min(maximumSegmentSize, 1<<16-1)), nil
}

func openVPNOuterTransportOverhead(protocol string, remoteAddress net.Addr) int {
	ipHeaderSize := ipv4HeaderMinLength
	remoteIP := M.SocksaddrFromNet(remoteAddress).Addr.Unmap()
	if remoteIP.Is6() || (!remoteIP.IsValid() && strings.HasSuffix(protocol, "6")) {
		ipHeaderSize = ipv6HeaderLength
	}
	if strings.HasPrefix(protocol, "tcp") {
		return ipHeaderSize + tcpHeaderMinLength
	}
	return ipHeaderSize + 8
}
