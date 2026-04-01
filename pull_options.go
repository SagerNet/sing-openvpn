package openvpn

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	pushRequestPayload       = "PUSH_REQUEST"
	legacyPullRequestPayload = "PULL_REQUEST"
	pushReplyPayloadPrefix   = "PUSH_REPLY"
	pushUpdatePayloadPrefix  = "PUSH_UPDATE"
)

type pushedOptionParseError struct {
	Name  string
	Value string
	Err   error
}

type pushedExcludedRoute struct {
	Name  string
	Value string
}

type wirePushedOptions struct {
	Topology             string
	TunMTU               uint32
	Ifconfig             []string
	IfconfigIPv6         []string
	RouteGateway         string
	Route                []string
	RouteIPv6            []string
	DNS                  []string
	DHCPOptions          []string
	BlockIPv6            bool
	BlockOutsideDNS      bool
	RedirectGateway      bool
	RedirectGatewayFlags []string
	RedirectPrivate      bool
	RouteMetric          int
	PingInterval         time.Duration
	PingRestart          time.Duration
	AuthToken            string
	AuthTokenUser        string
	PeerID               *uint32
	SelectedCipher       string
	SelectedAuth         string
	ProtocolFlags        []string
	KeyDerivation        string
	ExplicitExitNotify   uint32
	Compression          string
	CompressionLZO       string
	InactiveTimeout      time.Duration
	InactiveMinimumBytes uint64
	SessionTimeout       time.Duration
	PingExit             time.Duration
	PingTimerRemote      bool
}

type pushOptionsKind int

const (
	pushOptionsKindReply pushOptionsKind = iota
	pushOptionsKindUpdate
)

const peerIDMaxValue = (1 << 24) - 1

func appendPushReplyPayloadSegment(accumulatedFields []string, payload []byte) ([]string, int, bool) {
	payloadValue := normalizeControlPayload(payload)
	if payloadValue == "" {
		return accumulatedFields, 0, false
	}
	payloadFields := splitEscapedCommaFields(payloadValue)
	if len(payloadFields) == 0 {
		return accumulatedFields, 0, false
	}
	commandName := strings.TrimSpace(payloadFields[0])
	if !strings.EqualFold(commandName, pushReplyPayloadPrefix) &&
		!strings.EqualFold(commandName, pushUpdatePayloadPrefix) {
		return accumulatedFields, 0, false
	}
	if len(accumulatedFields) == 0 {
		accumulatedFields = append(accumulatedFields, commandName)
	}
	continuation := 0
	for _, payloadField := range payloadFields[1:] {
		optionName, optionValue, hasOption := parsePushReplyField(payloadField)
		if !hasOption {
			continue
		}
		if strings.EqualFold(optionName, "push-continuation") {
			continuationValue, err := strconv.Atoi(optionValue)
			if err == nil && continuationValue >= 0 && continuationValue <= 2 {
				continuation = continuationValue
			}
			continue
		}
		accumulatedFields = append(accumulatedFields, payloadField)
	}
	return accumulatedFields, continuation, true
}

func decodePushReplyPayload(payload []byte, remoteHost netip.Addr) (pushedOptions, int, bool) {
	payloadValue := normalizeControlPayload(payload)
	if payloadValue == "" {
		return pushedOptions{}, 0, false
	}
	payloadFields := splitEscapedCommaFields(payloadValue)
	if len(payloadFields) == 0 {
		return pushedOptions{}, 0, false
	}
	commandName := strings.TrimSpace(payloadFields[0])
	if !strings.EqualFold(commandName, pushReplyPayloadPrefix) &&
		!strings.EqualFold(commandName, pushUpdatePayloadPrefix) {
		return pushedOptions{}, 0, false
	}
	kind := pushOptionsKindReply
	if strings.EqualFold(commandName, pushUpdatePayloadPrefix) {
		kind = pushOptionsKindUpdate
	}
	var wireOptions wirePushedOptions
	var continuation int
	for _, payloadField := range payloadFields[1:] {
		optionName, optionValue, hasOption := parsePushReplyField(payloadField)
		if !hasOption {
			continue
		}
		switch strings.ToLower(optionName) {
		case "topology":
			if optionValue != "" {
				wireOptions.Topology = optionValue
			}
		case "tun-mtu":
			tunMTUValue, err := strconv.Atoi(optionValue)
			if err == nil && tunMTUValue > 0 {
				wireOptions.TunMTU = uint32(tunMTUValue)
			}
		case "ifconfig":
			if optionValue != "" {
				wireOptions.Ifconfig = append(wireOptions.Ifconfig, optionValue)
			}
		case "ifconfig-ipv6":
			if optionValue != "" {
				wireOptions.IfconfigIPv6 = append(wireOptions.IfconfigIPv6, optionValue)
			}
		case "route":
			if optionValue != "" {
				wireOptions.Route = append(wireOptions.Route, optionValue)
			}
		case "route-gateway":
			if optionValue != "" {
				wireOptions.RouteGateway = optionValue
			}
		case "route-ipv6":
			if optionValue != "" {
				wireOptions.RouteIPv6 = append(wireOptions.RouteIPv6, optionValue)
			}
		case "dns":
			if optionValue != "" {
				wireOptions.DNS = append(wireOptions.DNS, optionValue)
			}
		case "dhcp-option":
			if optionValue != "" {
				wireOptions.DHCPOptions = append(wireOptions.DHCPOptions, optionValue)
			}
		case "block-ipv6":
			wireOptions.BlockIPv6 = true
		case "block-outside-dns":
			wireOptions.BlockOutsideDNS = true
		case "redirect-gateway":
			wireOptions.RedirectGateway = true
			if optionValue != "" {
				wireOptions.RedirectGatewayFlags = strings.Fields(optionValue)
			}
		case "redirect-private":
			wireOptions.RedirectPrivate = true
		case "route-metric":
			routeMetricValue, err := strconv.Atoi(optionValue)
			if err == nil {
				wireOptions.RouteMetric = routeMetricValue
			}
		case "keepalive":
			keepaliveFields := strings.Fields(optionValue)
			if len(keepaliveFields) >= 2 {
				pingInterval, intervalErr := strconv.Atoi(keepaliveFields[0])
				pingRestart, restartErr := strconv.Atoi(keepaliveFields[1])
				if intervalErr == nil && restartErr == nil && pingInterval >= 0 && pingRestart >= 0 {
					wireOptions.PingInterval = time.Duration(pingInterval) * time.Second
					wireOptions.PingRestart = time.Duration(pingRestart) * time.Second
				}
			}
		case "ping":
			// Upstream helper_keepalive (helper.c) expands keepalive into
			// pushed ping and ping-restart directives.
			pingValue, err := strconv.Atoi(strings.TrimSpace(optionValue))
			if err == nil && pingValue >= 0 {
				wireOptions.PingInterval = time.Duration(pingValue) * time.Second
			}
		case "ping-restart":
			pingRestartValue, err := strconv.Atoi(strings.TrimSpace(optionValue))
			if err == nil && pingRestartValue >= 0 {
				wireOptions.PingRestart = time.Duration(pingRestartValue) * time.Second
			}
		case "auth-token":
			wireOptions.AuthToken = optionValue
		case "auth-token-user":
			wireOptions.AuthTokenUser = optionValue
		case "peer-id":
			peerIDValue, err := strconv.ParseUint(strings.TrimSpace(optionValue), 10, 32)
			if err == nil && peerIDValue <= peerIDMaxValue {
				peerIDCopy := uint32(peerIDValue)
				wireOptions.PeerID = &peerIDCopy
			}
		case "cipher":
			if optionValue != "" {
				wireOptions.SelectedCipher = optionValue
			}
		case "auth":
			if optionValue != "" {
				wireOptions.SelectedAuth = optionValue
			}
		case "protocol-flags":
			if optionValue != "" {
				wireOptions.ProtocolFlags = strings.Fields(optionValue)
			}
		case "key-derivation":
			if optionValue != "" {
				wireOptions.KeyDerivation = strings.ToLower(strings.TrimSpace(optionValue))
			}
		case "explicit-exit-notify":
			notifyValue, err := strconv.ParseUint(strings.TrimSpace(optionValue), 10, 32)
			if err == nil {
				wireOptions.ExplicitExitNotify = uint32(notifyValue)
			} else if optionValue == "" {
				wireOptions.ExplicitExitNotify = 1
			}
		case "compress":
			compressValue := strings.TrimSpace(optionValue)
			if compressValue == "" {
				// Upstream options_postprocess_mutate (options.c) maps bare
				// compress to stub.
				compressValue = "stub"
			}
			wireOptions.Compression = compressValue
		case "comp-lzo":
			compLZOValue := strings.TrimSpace(optionValue)
			if compLZOValue == "" {
				// Upstream options_postprocess_mutate (options.c) maps bare
				// comp-lzo to adaptive.
				compLZOValue = "adaptive"
			}
			wireOptions.CompressionLZO = compLZOValue
		case "inactive":
			inactiveFields := strings.Fields(optionValue)
			if len(inactiveFields) >= 1 {
				inactiveSeconds, err := strconv.Atoi(inactiveFields[0])
				if err == nil && inactiveSeconds >= 0 {
					wireOptions.InactiveTimeout = time.Duration(inactiveSeconds) * time.Second
				}
				if len(inactiveFields) >= 2 {
					// Upstream parse_inactive (options.c) clamps negative
					// minimum-bytes to 0.
					minimumBytes, minimumBytesErr := strconv.ParseInt(inactiveFields[1], 10, 64)
					if minimumBytesErr == nil && minimumBytes > 0 {
						wireOptions.InactiveMinimumBytes = uint64(minimumBytes)
					}
				}
			}
		case "session-timeout":
			sessionSeconds, err := strconv.Atoi(strings.TrimSpace(optionValue))
			if err == nil && sessionSeconds >= 0 {
				wireOptions.SessionTimeout = time.Duration(sessionSeconds) * time.Second
			}
		case "ping-exit":
			pingExitSeconds, err := strconv.Atoi(strings.TrimSpace(optionValue))
			if err == nil && pingExitSeconds >= 0 {
				wireOptions.PingExit = time.Duration(pingExitSeconds) * time.Second
			}
		case "ping-timer-rem":
			wireOptions.PingTimerRemote = true
		case "push-continuation":
			continuationValue, err := strconv.Atoi(optionValue)
			if err == nil && continuationValue >= 0 && continuationValue <= 2 {
				continuation = continuationValue
			}
		}
	}
	options := pushedOptionsFromWire(wireOptions, remoteHost)
	options.kind = kind
	return options, continuation, true
}

func pushedOptionsFromWire(wireOptions wirePushedOptions, remoteHost netip.Addr) pushedOptions {
	options := pushedOptions{
		Topology:             wireOptions.Topology,
		TunMTU:               wireOptions.TunMTU,
		DHCPOptions:          slices.Clone(wireOptions.DHCPOptions),
		BlockIPv6:            wireOptions.BlockIPv6,
		BlockOutsideDNS:      wireOptions.BlockOutsideDNS,
		RedirectGateway:      wireOptions.RedirectGateway,
		RedirectGatewayFlags: slices.Clone(wireOptions.RedirectGatewayFlags),
		RedirectPrivate:      wireOptions.RedirectPrivate,
		RouteMetric:          wireOptions.RouteMetric,
		PingInterval:         wireOptions.PingInterval,
		PingRestart:          wireOptions.PingRestart,
		AuthToken:            wireOptions.AuthToken,
		AuthTokenUser:        wireOptions.AuthTokenUser,
		PeerID:               wireOptions.PeerID,
		SelectedCipher:       wireOptions.SelectedCipher,
		SelectedAuth:         wireOptions.SelectedAuth,
		ProtocolFlags:        slices.Clone(wireOptions.ProtocolFlags),
		KeyDerivation:        wireOptions.KeyDerivation,
		ExplicitExitNotify:   wireOptions.ExplicitExitNotify,
		Compression:          wireOptions.Compression,
		CompressionLZO:       wireOptions.CompressionLZO,
		InactiveTimeout:      wireOptions.InactiveTimeout,
		InactiveMinimumBytes: wireOptions.InactiveMinimumBytes,
		SessionTimeout:       wireOptions.SessionTimeout,
		PingExit:             wireOptions.PingExit,
		PingTimerRemote:      wireOptions.PingTimerRemote,
	}
	for _, value := range wireOptions.Ifconfig {
		options.addWireIfconfig(value, wireOptions.Topology)
	}
	for _, value := range wireOptions.IfconfigIPv6 {
		options.addWireIfconfigIPv6(value)
	}
	options.setWireRouteGateway(wireOptions.RouteGateway)
	for _, value := range wireOptions.Route {
		options.addWireRoute(value, remoteHost)
	}
	for _, value := range wireOptions.RouteIPv6 {
		options.addWireRouteIPv6(value, remoteHost)
	}
	for _, value := range wireOptions.DNS {
		options.addWireDNSOptionV2(value)
	}
	for _, value := range wireOptions.DHCPOptions {
		options.addWireDHCPOptionDNS(value)
	}
	return options
}

func (options *pushedOptions) addWireIfconfig(value string, topology string) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return
	}
	prefix, err := parseIfconfigPrefix(raw, topology)
	if err != nil {
		options.addParseError("ifconfig", raw, err)
		return
	}
	options.LocalAddress = append(options.LocalAddress, pushedLocalAddress{
		Prefix: prefix,
		Peer:   parseIfconfigVPNGateway([]string{raw}, topology),
		Raw:    raw,
	})
}

func (options *pushedOptions) addWireIfconfigIPv6(value string) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return
	}
	prefix, err := parseIfconfigIPv6Prefix(raw)
	if err != nil {
		options.addParseError("ifconfig-ipv6", raw, err)
		return
	}
	options.LocalAddress = append(options.LocalAddress, pushedLocalAddress{
		Prefix: prefix,
		Peer:   parseIfconfigIPv6Peer(raw),
		Raw:    raw,
	})
}

func (options *pushedOptions) setWireRouteGateway(value string) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return
	}
	options.RouteGatewayRaw = raw
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return
	}
	if strings.EqualFold(fields[0], "vpn_gateway") {
		options.RouteGatewayVPN = true
		return
	}
	routeGateway, err := netip.ParseAddr(fields[0])
	if err != nil {
		options.addParseError("route-gateway", raw, errInvalidPushedRouteGateway)
		return
	}
	options.RouteGateway = routeGateway
}

func (options *pushedOptions) addWireRoute(value string, remoteHost netip.Addr) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return
	}
	prefix, gateway, metric, excluded, err := parsePushedRoute(raw, remoteHost)
	if err != nil {
		options.addParseError("route", raw, err)
		return
	}
	if excluded {
		options.addExcludedRoute("route", raw)
		return
	}
	options.Routes = append(options.Routes, pushedRoute{
		Route: TunnelRoute{
			Prefix:  prefix,
			Gateway: gateway,
			Metric:  metric,
		},
		Raw: raw,
	})
}

func (options *pushedOptions) addWireRouteIPv6(value string, remoteHost netip.Addr) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return
	}
	prefix, gateway, metric, excluded, err := parsePushedRouteIPv6(raw, remoteHost)
	if err != nil {
		options.addParseError("route-ipv6", raw, err)
		return
	}
	if excluded {
		options.addExcludedRoute("route-ipv6", raw)
		return
	}
	options.Routes = append(options.Routes, pushedRoute{
		Route: TunnelRoute{
			Prefix:  prefix,
			Gateway: gateway,
			Metric:  metric,
		},
		Raw: raw,
	})
}

func (options *pushedOptions) addWireDNSOptionV2(value string) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 || !strings.EqualFold(fields[0], "server") {
		return
	}
	if len(fields) < 3 {
		options.addParseError("dns", raw, E.New("invalid dns server option: ", raw))
		return
	}
	_, err := strconv.Atoi(fields[1])
	if err != nil {
		options.addParseError("dns", raw, E.Cause(err, "parse dns server priority: ", fields[1]))
		return
	}
	if !strings.EqualFold(fields[2], "address") {
		return
	}
	if len(fields) < 4 {
		options.addParseError("dns", raw, E.New("dns server address requires address value"))
		return
	}
	for _, addressValue := range fields[3:] {
		address, parseErr := netip.ParseAddr(addressValue)
		if parseErr != nil {
			options.addParseError("dns", raw, E.Cause(parseErr, "parse dns server address: ", addressValue))
			continue
		}
		options.DNS = append(options.DNS, pushedAddress{Address: address, Raw: raw, OptionName: "dns"})
	}
}

func (options *pushedOptions) addWireDHCPOptionDNS(value string) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return
	}
	optionName := strings.ToUpper(fields[0])
	if optionName != "DNS" && optionName != "DNS6" {
		return
	}
	if len(fields) < 2 {
		options.addParseError("dhcp-option", raw, E.New("dhcp-option ", optionName, " requires address value"))
		return
	}
	for _, addressValue := range fields[1:] {
		address, err := netip.ParseAddr(addressValue)
		if err != nil {
			options.addParseError("dhcp-option", raw, E.Cause(err, "parse dhcp-option ", optionName, " address: ", addressValue))
			continue
		}
		if optionName == "DNS" && !address.Is4() {
			options.addParseError("dhcp-option", raw, E.New("dhcp-option DNS expected IPv4 address: ", addressValue))
			continue
		}
		if optionName == "DNS6" && !address.Is6() {
			options.addParseError("dhcp-option", raw, E.New("dhcp-option DNS6 expected IPv6 address: ", addressValue))
			continue
		}
		options.DNS = append(options.DNS, pushedAddress{Address: address, Raw: raw, OptionName: "dhcp-option"})
	}
}

func (options *pushedOptions) addParseError(name string, value string, err error) {
	options.parseErrors = append(options.parseErrors, pushedOptionParseError{
		Name:  name,
		Value: value,
		Err:   err,
	})
}

func (options *pushedOptions) addExcludedRoute(name string, value string) {
	options.excludedRoutes = append(options.excludedRoutes, pushedExcludedRoute{
		Name:  name,
		Value: value,
	})
}

func parseIfconfigIPv6Peer(value string) netip.Addr {
	fields := strings.Fields(value)
	if len(fields) < 2 {
		return netip.Addr{}
	}
	peer, err := netip.ParseAddr(fields[1])
	if err != nil || !peer.Is6() {
		return netip.Addr{}
	}
	return peer
}

func normalizeControlPayload(payload []byte) string {
	trimmedPayload := strings.Trim(string(payload), "\x00")
	return strings.TrimSpace(trimmedPayload)
}

func splitEscapedCommaFields(value string) []string {
	if value == "" {
		return nil
	}
	fields := make([]string, 0, 8)
	var fieldBuilder strings.Builder
	escaped := false
	for _, character := range value {
		if escaped {
			fieldBuilder.WriteRune(character)
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if character == ',' {
			fields = append(fields, fieldBuilder.String())
			fieldBuilder.Reset()
			continue
		}
		fieldBuilder.WriteRune(character)
	}
	if escaped {
		fieldBuilder.WriteByte('\\')
	}
	fields = append(fields, fieldBuilder.String())
	return fields
}

func parsePushReplyField(value string) (string, string, bool) {
	fieldValue := strings.TrimSpace(value)
	if fieldValue == "" {
		return "", "", false
	}
	separatorIndex := strings.IndexAny(fieldValue, " \t")
	if separatorIndex < 0 {
		return fieldValue, "", true
	}
	optionName := fieldValue[:separatorIndex]
	optionValue := strings.TrimSpace(fieldValue[separatorIndex+1:])
	return optionName, optionValue, true
}

func formatInactivePullFilterValue(inactiveTimeout time.Duration, inactiveMinimumBytes uint64) string {
	if inactiveTimeout == 0 {
		return ""
	}
	result := strconv.FormatInt(int64(inactiveTimeout/time.Second), 10)
	if inactiveMinimumBytes > 0 {
		result += " " + strconv.FormatUint(inactiveMinimumBytes, 10)
	}
	return result
}
