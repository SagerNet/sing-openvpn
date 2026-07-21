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
	Route TunnelRoute
}

type pushedPingTimeoutAction uint8

const (
	pushedPingTimeoutNone pushedPingTimeoutAction = iota
	pushedPingTimeoutRestart
	pushedPingTimeoutExit
)

type wirePushedOptions struct {
	Topology              string
	TunMTU                uint32
	Ifconfig              string
	IfconfigIPv6          string
	RouteGateway          string
	Route                 []string
	RouteIPv6             []string
	DNS                   []string
	DHCPOptions           []string
	BlockIPv6             bool
	BlockOutsideDNS       bool
	RedirectGateway       bool
	RedirectGatewayFlags  []string
	RedirectPrivate       bool
	RouteMetric           int
	RouteMetricSet        bool
	PingInterval          time.Duration
	PingIntervalEnabled   bool
	PingRestart           time.Duration
	PingRestartEnabled    bool
	AuthToken             string
	AuthTokenUser         string
	PeerID                *uint32
	SelectedCipher        string
	SelectedAuth          string
	ProtocolFlags         []string
	KeyDerivation         string
	ExplicitExitNotify    uint32
	ExplicitExitNotifySet bool
	Compression           string
	CompressionLZO        string
	InactiveTimeout       time.Duration
	InactiveMinimumBytes  uint64
	InactiveTimeoutSet    bool
	SessionTimeout        time.Duration
	SessionTimeoutSet     bool
	PingExit              time.Duration
	PingExitSet           bool
	PingTimeoutAction     pushedPingTimeoutAction
	PingTimerRemote       bool
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

func decodePushReplyPayloadWithFilters(payload []byte, remoteHost netip.Addr, filters []PullFilter) (pushedOptions, int, bool) {
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
	var pullFilterRejection string
	for _, payloadField := range payloadFields[1:] {
		optionLine := strings.TrimLeft(payloadField, " \t\r\n\v\f")
		allowed, rejected := applyPullFilters(filters, optionLine)
		if rejected {
			pullFilterRejection = optionLine
			break
		}
		if !allowed {
			continue
		}
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
				wireOptions.Ifconfig = optionValue
			}
		case "ifconfig-ipv6":
			if optionValue != "" {
				wireOptions.IfconfigIPv6 = optionValue
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
			if optionValue != "" {
				wireOptions.RedirectGatewayFlags = strings.Fields(optionValue)
			}
		case "route-metric":
			routeMetricValue, err := strconv.Atoi(optionValue)
			if err == nil && routeMetricValue >= 0 {
				wireOptions.RouteMetric = routeMetricValue
				wireOptions.RouteMetricSet = true
			}
		case "ping":
			pingValue, err := strconv.Atoi(strings.TrimSpace(optionValue))
			if err == nil && pingValue >= 0 {
				wireOptions.PingInterval = time.Duration(pingValue) * time.Second
				wireOptions.PingIntervalEnabled = true
			}
		case "ping-restart":
			pingRestartValue, err := strconv.Atoi(strings.TrimSpace(optionValue))
			if err == nil && pingRestartValue >= 0 {
				wireOptions.PingRestart = time.Duration(pingRestartValue) * time.Second
				wireOptions.PingRestartEnabled = true
				wireOptions.PingTimeoutAction = pushedPingTimeoutRestart
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
				wireOptions.ExplicitExitNotifySet = true
			} else if optionValue == "" {
				wireOptions.ExplicitExitNotify = 1
				wireOptions.ExplicitExitNotifySet = true
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
					wireOptions.InactiveTimeoutSet = true
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
				wireOptions.SessionTimeoutSet = true
			}
		case "ping-exit":
			pingExitSeconds, err := strconv.Atoi(strings.TrimSpace(optionValue))
			if err == nil && pingExitSeconds >= 0 {
				wireOptions.PingExit = time.Duration(pingExitSeconds) * time.Second
				wireOptions.PingExitSet = true
				wireOptions.PingTimeoutAction = pushedPingTimeoutExit
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
	options.pullFilterRejection = pullFilterRejection
	return options, continuation, true
}

func applyPullFilters(filters []PullFilter, optionLine string) (bool, bool) {
	for _, filter := range filters {
		if !strings.HasPrefix(optionLine, filter.Text) {
			continue
		}
		switch filter.Action {
		case "accept":
			return true, false
		case "ignore":
			return false, false
		case "reject":
			return false, true
		}
	}
	return true, false
}

func pushedOptionsFromWire(wireOptions wirePushedOptions, remoteHost netip.Addr) pushedOptions {
	options := pushedOptions{
		Topology:              wireOptions.Topology,
		TunMTU:                wireOptions.TunMTU,
		DHCPOptions:           slices.Clone(wireOptions.DHCPOptions),
		BlockIPv6:             wireOptions.BlockIPv6,
		BlockOutsideDNS:       wireOptions.BlockOutsideDNS,
		RedirectGateway:       wireOptions.RedirectGateway,
		RedirectGatewayFlags:  slices.Clone(wireOptions.RedirectGatewayFlags),
		RedirectPrivate:       wireOptions.RedirectPrivate,
		RouteMetric:           wireOptions.RouteMetric,
		RouteMetricSet:        wireOptions.RouteMetricSet,
		PingInterval:          wireOptions.PingInterval,
		PingIntervalEnabled:   wireOptions.PingIntervalEnabled,
		PingRestart:           wireOptions.PingRestart,
		PingRestartEnabled:    wireOptions.PingRestartEnabled,
		AuthToken:             wireOptions.AuthToken,
		AuthTokenUser:         wireOptions.AuthTokenUser,
		PeerID:                wireOptions.PeerID,
		SelectedCipher:        wireOptions.SelectedCipher,
		SelectedAuth:          wireOptions.SelectedAuth,
		ProtocolFlags:         slices.Clone(wireOptions.ProtocolFlags),
		KeyDerivation:         wireOptions.KeyDerivation,
		ExplicitExitNotify:    wireOptions.ExplicitExitNotify,
		ExplicitExitNotifySet: wireOptions.ExplicitExitNotifySet,
		Compression:           wireOptions.Compression,
		CompressionLZO:        wireOptions.CompressionLZO,
		InactiveTimeout:       wireOptions.InactiveTimeout,
		InactiveMinimumBytes:  wireOptions.InactiveMinimumBytes,
		InactiveTimeoutSet:    wireOptions.InactiveTimeoutSet,
		SessionTimeout:        wireOptions.SessionTimeout,
		SessionTimeoutSet:     wireOptions.SessionTimeoutSet,
		PingExit:              wireOptions.PingExit,
		PingExitSet:           wireOptions.PingExitSet,
		PingTimerRemote:       wireOptions.PingTimerRemote,
	}
	switch wireOptions.PingTimeoutAction {
	case pushedPingTimeoutRestart:
		options.PingExit = 0
		options.PingExitSet = false
	case pushedPingTimeoutExit:
		options.PingRestart = 0
		options.PingRestartEnabled = false
	}
	if wireOptions.Ifconfig != "" {
		options.addWireIfconfig(wireOptions.Ifconfig, wireOptions.Topology)
	}
	if wireOptions.IfconfigIPv6 != "" {
		options.addWireIfconfigIPv6(wireOptions.IfconfigIPv6)
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
	options.DNSServers = slices.DeleteFunc(options.DNSServers, func(server TunnelDNSServer) bool {
		if len(server.Addresses) > 0 {
			return false
		}
		options.addParseError("dns", "server "+strconv.Itoa(server.Priority), E.New("dns server has no address assigned"))
		return true
	})
	options.modernDNS = len(options.DNSServers) > 0
	for _, value := range wireOptions.DHCPOptions {
		if !options.modernDNS {
			options.addWireDHCPOptionDNS(value)
		}
	}
	if options.modernDNS {
		options.DHCPOptions = filterOpenVPNNonDNSDHCPOptions(options.DHCPOptions)
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
		options.addExcludedRoute("route", raw, TunnelRoute{Prefix: prefix, Metric: metric})
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
		options.addExcludedRoute("route-ipv6", raw, TunnelRoute{Prefix: prefix, Metric: metric})
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
	if len(fields) == 0 {
		return
	}
	if strings.EqualFold(fields[0], "search-domains") {
		if len(fields) < 2 {
			options.addParseError("dns", raw, E.New("dns search-domains requires domain value"))
			return
		}
		for _, domain := range fields[1:] {
			if !validateTunnelDNSDomain(domain) {
				options.addParseError("dns", raw, E.New("dns search domain contains invalid characters: ", domain))
				continue
			}
			options.SearchDomains = appendUniqueStringValues(options.SearchDomains, []string{domain})
			options.modernSearchDomains = appendUniqueStringValues(options.modernSearchDomains, []string{domain})
		}
		return
	}
	if !strings.EqualFold(fields[0], "server") {
		return
	}
	if len(fields) < 3 {
		options.addParseError("dns", raw, E.New("invalid dns server option: ", raw))
		return
	}
	priority, err := strconv.Atoi(fields[1])
	if err != nil {
		options.addParseError("dns", raw, E.Cause(err, "parse dns server priority: ", fields[1]))
		return
	}
	if priority < 0 || priority > 127 {
		options.addParseError("dns", raw, E.New("pushed dns server priority must be between 0 and 127"))
		return
	}
	server := options.tunnelDNSServer(priority)
	switch strings.ToLower(fields[2]) {
	case "address":
		if len(fields) < 4 {
			options.addParseError("dns", raw, E.New("dns server address requires address value"))
			return
		}
		for _, addressValue := range fields[3:] {
			if len(server.Addresses) >= maxTunnelDNSServerAddresses {
				options.addParseError("dns", raw, E.New("dns server address maximum exceeded: ", addressValue))
				return
			}
			address, parseErr := parseTunnelDNSAddress(addressValue)
			if parseErr != nil {
				options.addParseError("dns", raw, E.Cause(parseErr, "parse dns server address: ", addressValue))
				continue
			}
			server.Addresses = append(server.Addresses, address)
			modernAddress := pushedAddress{Address: address.Addr(), Raw: raw, OptionName: "dns"}
			options.DNS = append(options.DNS, modernAddress)
			options.modernDNSAddresses = append(options.modernDNSAddresses, modernAddress)
		}
	case "resolve-domains":
		if len(fields) < 4 {
			options.addParseError("dns", raw, E.New("dns server resolve-domains requires domain value"))
			return
		}
		for _, domain := range fields[3:] {
			if !validateTunnelDNSDomain(domain) {
				options.addParseError("dns", raw, E.New("dns resolve domain contains invalid characters: ", domain))
				continue
			}
			server.ResolveDomains = appendUniqueStringValues(server.ResolveDomains, []string{domain})
		}
	case "dnssec":
		if len(fields) != 4 {
			options.addParseError("dns", raw, E.New("dns server dnssec requires one value"))
			return
		}
		dnssec := strings.ToLower(fields[3])
		switch dnssec {
		case "yes", "optional", "no":
			server.DNSSEC = dnssec
		default:
			options.addParseError("dns", raw, E.New("invalid dnssec mode: ", fields[3]))
		}
	case "transport":
		if len(fields) != 4 {
			options.addParseError("dns", raw, E.New("dns server transport requires one value"))
			return
		}
		switch fields[3] {
		case "plain":
			server.Transport = "plain"
		case "DoT":
			server.Transport = "dot"
		case "DoH":
			server.Transport = "doh"
		default:
			options.addParseError("dns", raw, E.New("invalid dns transport: ", fields[3]))
		}
	case "sni":
		if len(fields) != 4 {
			options.addParseError("dns", raw, E.New("dns server sni requires one value"))
			return
		}
		if !validateTunnelDNSDomain(fields[3]) {
			options.addParseError("dns", raw, E.New("dns server sni contains invalid characters: ", fields[3]))
			return
		}
		server.SNI = fields[3]
	default:
		options.addParseError("dns", raw, E.New("unsupported dns server option: ", fields[2]))
	}
}

func (options *pushedOptions) tunnelDNSServer(priority int) *TunnelDNSServer {
	for i := range options.DNSServers {
		if options.DNSServers[i].Priority == priority {
			return &options.DNSServers[i]
		}
	}
	options.DNSServers = append(options.DNSServers, TunnelDNSServer{Priority: priority})
	return &options.DNSServers[len(options.DNSServers)-1]
}

func parseTunnelDNSAddress(value string) (netip.AddrPort, error) {
	address, err := netip.ParseAddr(value)
	if err == nil {
		return netip.AddrPortFrom(address, 0), nil
	}
	addressPort, addressPortErr := netip.ParseAddrPort(value)
	if addressPortErr != nil {
		return netip.AddrPort{}, addressPortErr
	}
	if addressPort.Port() == 0 {
		return netip.AddrPort{}, E.New("dns server port must not be zero")
	}
	return addressPort, nil
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
	if optionName == "DOMAIN" || optionName == "ADAPTER_DOMAIN_SUFFIX" || optionName == "DOMAIN-SEARCH" {
		if len(fields) < 2 {
			options.addParseError("dhcp-option", raw, E.New("dhcp-option ", optionName, " requires domain value"))
			return
		}
		for _, domain := range fields[1:] {
			if !validateTunnelDNSDomain(domain) {
				options.addParseError("dhcp-option", raw, E.New("dhcp-option ", optionName, " contains invalid domain: ", domain))
				continue
			}
			options.SearchDomains = appendUniqueStringValues(options.SearchDomains, []string{domain})
		}
		return
	}
	if optionName == "DOMAIN-ROUTE" {
		if len(fields) < 2 {
			options.addParseError("dhcp-option", raw, E.New("dhcp-option DOMAIN-ROUTE requires domain value"))
			return
		}
		for _, domain := range fields[1:] {
			if !validateTunnelDNSDomain(domain) {
				options.addParseError("dhcp-option", raw, E.New("dhcp-option DOMAIN-ROUTE contains invalid domain: ", domain))
				continue
			}
			options.DNSRoutes = appendUniqueStringValues(options.DNSRoutes, []string{domain})
		}
		return
	}
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

func filterOpenVPNNonDNSDHCPOptions(values []string) []string {
	return slices.DeleteFunc(slices.Clone(values), func(value string) bool {
		fields := strings.Fields(value)
		if len(fields) == 0 {
			return false
		}
		switch strings.ToUpper(fields[0]) {
		case "DNS", "DNS6", "DOMAIN", "ADAPTER_DOMAIN_SUFFIX", "DOMAIN-SEARCH", "DOMAIN-ROUTE":
			return true
		default:
			return false
		}
	})
}

func (options *pushedOptions) addParseError(name string, value string, err error) {
	options.parseErrors = append(options.parseErrors, pushedOptionParseError{
		Name:  name,
		Value: value,
		Err:   err,
	})
}

func (options *pushedOptions) addExcludedRoute(name string, value string, route TunnelRoute) {
	options.excludedRoutes = append(options.excludedRoutes, pushedExcludedRoute{
		Name:  name,
		Value: value,
		Route: route,
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
