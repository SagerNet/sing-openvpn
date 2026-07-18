package openvpn

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

func tlsServerCipher(peerInfo string, optionsString string, options ServerOptions) (string, error) {
	serverCiphers := tlsAdvertisedDataCiphers(options.DataChannel.Ciphers)
	clientCiphers, clientCipherListKnown := parsePeerInfoCipherList(peerInfo)
	remoteCipher := strings.TrimSpace(extractRemoteCipherName(optionsString))
	if clientCipherListKnown {
		remoteCipher = ""
	}
	for _, serverCipher := range serverCiphers {
		for _, clientCipher := range clientCiphers {
			if strings.EqualFold(serverCipher, clientCipher) {
				return serverCipher, nil
			}
		}
		if remoteCipher != "" && strings.EqualFold(serverCipher, remoteCipher) {
			return serverCipher, nil
		}
	}
	if clientCipherListKnown || remoteCipher != "" {
		return "", E.Extend(ErrCipherNegotiationFailed, "no shared cipher")
	}
	if options.DataChannel.FallbackCipher != "" {
		return options.DataChannel.FallbackCipher, nil
	}
	return "", E.Extend(ErrCipherNegotiationFailed, "no shared cipher")
}

func parsePeerInfoCipherList(peerInfo string) ([]string, bool) {
	for line := range strings.SplitSeq(peerInfo, "\n") {
		if !strings.HasPrefix(line, "IV_CIPHERS=") {
			continue
		}
		return splitPeerInfoCipherList(strings.TrimPrefix(line, "IV_CIPHERS=")), true
	}
	if peerInfoNCPVersion(peerInfo) >= 2 {
		return []string{"AES-256-GCM", "AES-128-GCM"}, true
	}
	return nil, false
}

func splitPeerInfoCipherList(value string) []string {
	var ciphers []string
	for cipherName := range strings.SplitSeq(value, ":") {
		trimmedCipherName := strings.TrimSpace(cipherName)
		if trimmedCipherName == "" {
			continue
		}
		ciphers = append(ciphers, trimmedCipherName)
	}
	return ciphers
}

func peerInfoNCPVersion(peerInfo string) int {
	for line := range strings.SplitSeq(peerInfo, "\n") {
		trimmedLine := strings.TrimRight(line, "\r")
		if !strings.HasPrefix(trimmedLine, "IV_NCP=") {
			continue
		}
		parsedValue, err := strconv.Atoi(strings.TrimPrefix(trimmedLine, "IV_NCP="))
		if err != nil {
			return 0
		}
		return parsedValue
	}
	return 0
}

const (
	serverPushBundleSize     = 1024
	serverPushBundleOverhead = 84
	serverPushSafeCapacity   = serverPushBundleSize - serverPushBundleOverhead
)

func buildServerPushReplyPayloadsWithOverrides(options ServerOptions, peerInfo string, selectedCipher string, peerID *uint32, ifconfigOverride pushedLocalAddress, ifconfigIPv6Override pushedLocalAddress, serverIPv4 netip.Addr) ([][]byte, error) {
	serverPushOptions := buildPushedOptions(options)
	if _, supportsPushMTU := peerInfoMTU(peerInfo); !supportsPushMTU {
		serverPushOptions.TunMTU = 0
	}
	if ifconfigOverride.Prefix.IsValid() {
		serverPushOptions.LocalAddress = replacePushedLocalAddressByFamily(serverPushOptions.LocalAddress, ifconfigOverride)
	}
	if ifconfigIPv6Override.Prefix.IsValid() {
		serverPushOptions.LocalAddress = replacePushedLocalAddressByFamily(serverPushOptions.LocalAddress, ifconfigIPv6Override)
	}
	if serverIPv4.Is4() {
		topology, topologyErr := resolveIPv4PoolTopology(options.Tunnel.Topology)
		if topologyErr == nil {
			switch topology {
			case ipv4TopologySubnet:
				if !serverPushOptions.RouteGateway.IsValid() && !serverPushOptions.RouteGatewayVPN && serverPushOptions.RouteGatewayRaw == "" {
					serverPushOptions.RouteGateway = serverIPv4
				}
			case ipv4TopologyNet30:
				serverRoute := TunnelRoute{Prefix: netip.PrefixFrom(serverIPv4, 32)}
				serverPushOptions.Routes = appendUniquePushedRoutes(serverPushOptions.Routes, serverRoute)
			}
		}
	}
	fields := buildPushReplyOptionFields(serverPushOptions)
	_, hasCipherList := parsePeerInfoCipherList(peerInfo)
	if selectedCipher != "" && (hasCipherList || peerInfoNCPVersion(peerInfo) >= 2) {
		fields = append(fields, "cipher "+selectedCipher)
	}
	if peerID != nil && peerSupportsIVProtoFlag(peerInfo, tlsIVProtoDataV2) {
		fields = append(fields, "peer-id "+strconv.FormatUint(uint64(*peerID), 10))
	}
	supportsCCExit := peerSupportsIVProtoFlag(peerInfo, tlsIVProtoCCExitNotify)
	supportsTLSKeyExport := peerSupportsIVProtoFlag(peerInfo, tlsIVProtoTLSKeyExport)
	if supportsCCExit {
		protocolFlags := []string{"cc-exit"}
		if supportsTLSKeyExport {
			protocolFlags = append(protocolFlags, "tls-ekm")
		}
		fields = append(fields, "protocol-flags "+strings.Join(protocolFlags, " "))
	} else if supportsTLSKeyExport {
		fields = append(fields, "key-derivation tls-ekm")
	}
	return splitServerPushReplyFields(fields)
}

func splitServerPushReplyFields(fields []string) ([][]byte, error) {
	if len(fields) == 0 || fields[0] != pushReplyPayloadPrefix {
		return nil, E.New("invalid OpenVPN push reply fields")
	}
	current := pushReplyPayloadPrefix
	multiPush := false
	payloads := make([][]byte, 0, 1)
	for _, field := range fields[1:] {
		addition := "," + field
		if len(current)+len(addition) >= serverPushSafeCapacity {
			if current == pushReplyPayloadPrefix {
				return nil, E.New("OpenVPN push option is too long: ", field)
			}
			payloads = append(payloads, []byte(current+",push-continuation 2"))
			current = pushReplyPayloadPrefix
			multiPush = true
		}
		if len(current)+len(addition) >= serverPushSafeCapacity {
			return nil, E.New("OpenVPN push option is too long: ", field)
		}
		current += addition
	}
	if multiPush {
		current += ",push-continuation 1"
	}
	return append(payloads, []byte(current)), nil
}

func appendUniquePushedRoutes(routes []pushedRoute, route TunnelRoute) []pushedRoute {
	if slices.ContainsFunc(routes, func(existingRoute pushedRoute) bool {
		return existingRoute.Route == route
	}) {
		return routes
	}
	return append(routes, pushedRoute{Route: route})
}
