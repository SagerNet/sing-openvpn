package openvpn

import "encoding/binary"

const (
	ipHeaderVersionIPv4 = 4
	ipHeaderVersionIPv6 = 6
	ipv4HeaderMinLength = 20
	ipv6HeaderLength    = 40
	ipProtocolTCP       = 6

	tcpHeaderMinLength = 20
	tcpFlagSYN         = 0x02
	tcpOptionKindEnd   = 0
	tcpOptionKindNOP   = 1
	tcpOptionKindMSS   = 2
	tcpMSSOptionLength = 4
)

// Upstream mss_fixup_ipv4/mss_fixup_ipv6 treats the cap as IPv4 MSS;
// IPv6 subtracts the 20-byte header delta before comparison.
func clampTCPSegmentMSS(packet []byte, maxSegmentSize uint16) []byte {
	if maxSegmentSize == 0 {
		return packet
	}
	effectiveMaxSegmentSize := maxSegmentSize
	if len(packet) >= 1 && packet[0]>>4 == ipHeaderVersionIPv6 {
		const ipv6MSSHeaderOverhead = ipv6HeaderLength - ipv4HeaderMinLength
		if effectiveMaxSegmentSize <= ipv6MSSHeaderOverhead {
			return packet
		}
		effectiveMaxSegmentSize -= ipv6MSSHeaderOverhead
	}
	tcpHeaderOffset, mssValueOffset, advertisedMSS, hasMSS := locateTCPSYNMSSOption(packet)
	if !hasMSS || advertisedMSS <= effectiveMaxSegmentSize {
		return packet
	}
	clonedPacket := append([]byte{}, packet...)
	binary.BigEndian.PutUint16(clonedPacket[mssValueOffset:mssValueOffset+2], effectiveMaxSegmentSize)
	checksumOffset := tcpHeaderOffset + 16
	currentChecksum := binary.BigEndian.Uint16(clonedPacket[checksumOffset : checksumOffset+2])
	updatedChecksum := incrementallyUpdateChecksum16(currentChecksum, advertisedMSS, effectiveMaxSegmentSize)
	binary.BigEndian.PutUint16(clonedPacket[checksumOffset:checksumOffset+2], updatedChecksum)
	return clonedPacket
}

func locateTCPSYNMSSOption(packet []byte) (tcpHeaderOffset int, mssValueOffset int, advertisedMSS uint16, hasMSS bool) {
	if len(packet) < 1 {
		return 0, 0, 0, false
	}
	var ipHeaderLength int
	switch packet[0] >> 4 {
	case ipHeaderVersionIPv4:
		if len(packet) < ipv4HeaderMinLength {
			return 0, 0, 0, false
		}
		ihl := int(packet[0]&0x0f) * 4
		if ihl < ipv4HeaderMinLength || ihl > len(packet) {
			return 0, 0, 0, false
		}
		if packet[9] != ipProtocolTCP {
			return 0, 0, 0, false
		}
		ipHeaderLength = ihl
	case ipHeaderVersionIPv6:
		if len(packet) < ipv6HeaderLength {
			return 0, 0, 0, false
		}
		if packet[6] != ipProtocolTCP {
			return 0, 0, 0, false
		}
		ipHeaderLength = ipv6HeaderLength
	default:
		return 0, 0, 0, false
	}
	tcpSegment := packet[ipHeaderLength:]
	if len(tcpSegment) < tcpHeaderMinLength {
		return 0, 0, 0, false
	}
	dataOffset := int(tcpSegment[12]>>4) * 4
	if dataOffset < tcpHeaderMinLength || dataOffset > len(tcpSegment) {
		return 0, 0, 0, false
	}
	if tcpSegment[13]&tcpFlagSYN == 0 {
		return 0, 0, 0, false
	}
	optionsArea := tcpSegment[tcpHeaderMinLength:dataOffset]
	optionOffset := 0
	for optionOffset < len(optionsArea) {
		kind := optionsArea[optionOffset]
		if kind == tcpOptionKindEnd {
			return 0, 0, 0, false
		}
		if kind == tcpOptionKindNOP {
			optionOffset++
			continue
		}
		if optionOffset+1 >= len(optionsArea) {
			return 0, 0, 0, false
		}
		length := int(optionsArea[optionOffset+1])
		if length < 2 || optionOffset+length > len(optionsArea) {
			return 0, 0, 0, false
		}
		if kind == tcpOptionKindMSS && length == tcpMSSOptionLength {
			advertisedMSS = binary.BigEndian.Uint16(optionsArea[optionOffset+2 : optionOffset+4])
			tcpHeaderOffset = ipHeaderLength
			mssValueOffset = ipHeaderLength + tcpHeaderMinLength + optionOffset + 2
			return tcpHeaderOffset, mssValueOffset, advertisedMSS, true
		}
		optionOffset += length
	}
	return 0, 0, 0, false
}

func incrementallyUpdateChecksum16(currentChecksum uint16, oldWord uint16, newWord uint16) uint16 {
	sum := uint32(^currentChecksum) + uint32(^oldWord) + uint32(newWord)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
