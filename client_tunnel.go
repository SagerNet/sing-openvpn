package openvpn

import (
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

type clientTunnelState struct {
	access                   sync.RWMutex
	configuration            TunnelConfiguration
	authToken                string
	authTokenUser            string
	pulledOptionsReceived    bool
	deferInitialEvent        bool
	pullFilterRejection      string
	compressionPushRejection string
	dispatcher               clientTunnelConfigurationDispatcher
}

type clientTunnelConfigurationDispatcher struct {
	events  []TunnelConfigurationEvent
	wake    chan struct{}
	started bool
	stopped bool
}

func (c *Client) TunnelConfiguration() TunnelConfiguration {
	c.tunnel.access.RLock()
	defer c.tunnel.access.RUnlock()
	return cloneTunnelConfiguration(c.tunnel.configuration)
}

func (c *Client) emitTunnelConfigurationEvent(reason TunnelConfigurationEventReason) {
	if c.options.OnTunnelConfiguration == nil {
		return
	}
	c.tunnel.access.Lock()
	configurationSnapshot := cloneTunnelConfiguration(c.tunnel.configuration)
	eventQueued := c.enqueueTunnelConfigurationEventLocked(TunnelConfigurationEvent{
		Reason:        reason,
		Configuration: configurationSnapshot,
	})
	c.tunnel.access.Unlock()
	if eventQueued {
		c.signalTunnelConfigurationEvent()
	}
}

func (c *Client) startTunnelConfigurationDispatcher() {
	if c.options.OnTunnelConfiguration == nil {
		return
	}
	c.tunnel.access.Lock()
	if c.tunnel.dispatcher.started || c.tunnel.dispatcher.stopped {
		c.tunnel.access.Unlock()
		return
	}
	c.tunnel.dispatcher.started = true
	c.tunnel.access.Unlock()
	go c.runTunnelConfigurationDispatcher()
}

func (c *Client) enqueueTunnelConfigurationEventLocked(event TunnelConfigurationEvent) bool {
	if c.options.OnTunnelConfiguration == nil || c.tunnel.dispatcher.stopped {
		return false
	}
	c.tunnel.dispatcher.events = append(c.tunnel.dispatcher.events, event)
	return true
}

func (c *Client) signalTunnelConfigurationEvent() {
	select {
	case c.tunnel.dispatcher.wake <- struct{}{}:
	default:
	}
}

func (c *Client) runTunnelConfigurationDispatcher() {
	for {
		c.tunnel.access.Lock()
		if c.tunnel.dispatcher.stopped {
			c.tunnel.dispatcher.events = nil
			c.tunnel.access.Unlock()
			return
		}
		if len(c.tunnel.dispatcher.events) == 0 {
			c.tunnel.access.Unlock()
			<-c.tunnel.dispatcher.wake
			continue
		}
		event := c.tunnel.dispatcher.events[0]
		c.tunnel.dispatcher.events[0] = TunnelConfigurationEvent{}
		c.tunnel.dispatcher.events = c.tunnel.dispatcher.events[1:]
		c.tunnel.access.Unlock()
		err := c.options.OnTunnelConfiguration(event)
		if err != nil {
			c.failSessionForTunnelConfiguration(err)
		}
	}
}

func (c *Client) failSessionForTunnelConfiguration(err error) {
	failure := E.Cause(err, "openvpn: apply tunnel configuration")
	if c.options.Logger != nil {
		c.options.Logger.WarnContext(c.options.Context, failure)
	}
	c.lifecycle.access.Lock()
	session := c.lifecycle.currentSession
	c.lifecycle.access.Unlock()
	if session != nil {
		session.Fail(failure)
	}
}

func (c *Client) stopTunnelConfigurationDispatcher() {
	c.tunnel.access.Lock()
	c.tunnel.dispatcher.stopped = true
	c.tunnel.dispatcher.events = nil
	c.tunnel.access.Unlock()
	c.signalTunnelConfigurationEvent()
}

func (c *Client) applyPushedOptions(options pushedOptions) {
	c.tunnel.access.Lock()
	c.tunnel.pullFilterRejection = ""
	c.tunnel.compressionPushRejection = ""
	isInitialPulledOptions := !c.tunnel.pulledOptionsReceived
	deferInitialTunnelEvent := isInitialPulledOptions && c.tunnel.deferInitialEvent
	eventReason := TunnelConfigurationEventInitial
	if !isInitialPulledOptions {
		eventReason = TunnelConfigurationEventRenegotiation
	}
	if options.kind == pushOptionsKindUpdate {
		eventReason = TunnelConfigurationEventPushUpdate
	}
	c.tunnel.pulledOptionsReceived = true
	updatedConfiguration := cloneTunnelConfiguration(c.tunnel.configuration)
	if updatedConfiguration.Topology == "" && options.Topology != "" {
		updatedConfiguration.Topology = options.Topology
	}
	c.warnPushedOptionParseErrors(options.parseErrors)
	c.debugPushedExcludedRoutes(options.excludedRoutes)
	filteredLocalIPv4 := c.filterPushedLocalAddressValues("ifconfig", options.localAddressByFamily(true), updatedConfiguration.Topology)
	if len(updatedConfiguration.LocalIPv4) == 0 && len(filteredLocalIPv4) > 0 {
		localIPv4, vpnGateway := pushedLocalAddressPrefixes(filteredLocalIPv4)
		updatedConfiguration.LocalIPv4 = localIPv4
		if vpnGateway.IsValid() {
			updatedConfiguration.VPNGateway = vpnGateway
		}
	}
	filteredLocalIPv6 := c.filterPushedLocalAddressValues("ifconfig-ipv6", options.localAddressByFamily(false), updatedConfiguration.Topology)
	if len(updatedConfiguration.LocalIPv6) == 0 && len(filteredLocalIPv6) > 0 {
		localIPv6, vpnGatewayIPv6 := pushedLocalAddressPrefixes(filteredLocalIPv6)
		updatedConfiguration.LocalIPv6 = localIPv6
		if vpnGatewayIPv6.IsValid() {
			updatedConfiguration.VPNGatewayIPv6 = vpnGatewayIPv6
		}
	}
	if updatedConfiguration.TunMTU == 0 && options.TunMTU > 0 {
		updatedConfiguration.TunMTU = options.TunMTU
	}
	updatedConfiguration.DNS = appendUniqueAddresses(updatedConfiguration.DNS, pushedAddresses(c.filterPushedAddressValues("dns", options.DNS)))
	updatedConfiguration.DHCPOptions = appendUniqueStringValues(updatedConfiguration.DHCPOptions, c.filterPulledOptionValues("dhcp-option", options.DHCPOptions))
	if options.BlockIPv6 && c.allowPulledOption("block-ipv6", "") {
		updatedConfiguration.BlockIPv6 = true
	}
	if options.BlockOutsideDNS && c.allowPulledOption("block-outside-dns", "") {
		updatedConfiguration.BlockOutsideDNS = true
	}
	if options.RouteMetric != 0 && updatedConfiguration.RouteMetric == 0 && c.allowPulledOption("route-metric", strconv.Itoa(options.RouteMetric)) {
		updatedConfiguration.RouteMetric = options.RouteMetric
	}
	if options.PingInterval > 0 && options.PingRestart > 0 &&
		updatedConfiguration.PingInterval == 0 && updatedConfiguration.PingRestart == 0 &&
		c.allowPulledOption("keepalive", strconv.FormatInt(int64(options.PingInterval/time.Second), 10)+" "+strconv.FormatInt(int64(options.PingRestart/time.Second), 10)) {
		updatedConfiguration.PingInterval = options.PingInterval
		updatedConfiguration.PingRestart = options.PingRestart
	}
	if options.AuthToken != "" && c.allowPulledOption("auth-token", options.AuthToken) {
		updatedConfiguration.AuthToken = options.AuthToken
		c.tunnel.authToken = options.AuthToken
	}
	if options.AuthTokenUser != "" && c.allowPulledOption("auth-token-user", options.AuthTokenUser) {
		updatedConfiguration.AuthTokenUser = options.AuthTokenUser
		c.tunnel.authTokenUser = options.AuthTokenUser
	}
	if options.ExplicitExitNotify > 0 && updatedConfiguration.ExplicitExitNotify == 0 &&
		c.allowPulledOption("explicit-exit-notify", strconv.FormatUint(uint64(options.ExplicitExitNotify), 10)) {
		updatedConfiguration.ExplicitExitNotify = options.ExplicitExitNotify
	}
	if options.PeerID != nil && updatedConfiguration.PeerID == nil &&
		c.allowPulledOption("peer-id", strconv.FormatUint(uint64(*options.PeerID), 10)) {
		peerIDValue := *options.PeerID
		updatedConfiguration.PeerID = &peerIDValue
	}
	if options.SelectedCipher != "" && updatedConfiguration.SelectedCipher == "" &&
		c.allowPulledOption("cipher", options.SelectedCipher) {
		updatedConfiguration.SelectedCipher = options.SelectedCipher
	}
	if options.SelectedAuth != "" && updatedConfiguration.SelectedAuth == "" &&
		c.allowPulledOption("auth", options.SelectedAuth) {
		updatedConfiguration.SelectedAuth = options.SelectedAuth
	}
	if len(options.ProtocolFlags) > 0 && len(updatedConfiguration.ProtocolFlags) == 0 &&
		c.allowPulledOption("protocol-flags", strings.Join(options.ProtocolFlags, " ")) {
		updatedConfiguration.ProtocolFlags = slices.Clone(options.ProtocolFlags)
	}
	if options.KeyDerivation != "" && updatedConfiguration.KeyDerivation == "" &&
		c.allowPulledOption("key-derivation", options.KeyDerivation) {
		updatedConfiguration.KeyDerivation = options.KeyDerivation
	}
	if options.InactiveTimeout > 0 && updatedConfiguration.InactiveTimeout == 0 &&
		c.allowPulledOption("inactive", formatInactivePullFilterValue(options.InactiveTimeout, options.InactiveMinimumBytes)) {
		updatedConfiguration.InactiveTimeout = options.InactiveTimeout
		updatedConfiguration.InactiveMinimumBytes = options.InactiveMinimumBytes
	}
	if options.SessionTimeout > 0 && updatedConfiguration.SessionTimeout == 0 &&
		c.allowPulledOption("session-timeout", strconv.FormatInt(int64(options.SessionTimeout/time.Second), 10)) {
		updatedConfiguration.SessionTimeout = options.SessionTimeout
	}
	if options.PingExit > 0 && updatedConfiguration.PingExit == 0 &&
		c.allowPulledOption("ping-exit", strconv.FormatInt(int64(options.PingExit/time.Second), 10)) {
		updatedConfiguration.PingExit = options.PingExit
	}
	if options.PingTimerRemote && !updatedConfiguration.PingTimerRemote &&
		c.allowPulledOption("ping-timer-rem", "") {
		updatedConfiguration.PingTimerRemote = true
	}
	if !c.options.Pull.RouteNoPull {
		effectiveRouteGateway := updatedConfiguration.RouteGateway
		if !effectiveRouteGateway.IsValid() &&
			(options.RouteGateway.IsValid() || options.RouteGatewayVPN) &&
			c.allowPulledOption("route-gateway", options.routeGatewayFilterValue()) {
			effectiveRouteGateway = options.routeGateway(updatedConfiguration.VPNGateway, updatedConfiguration.Topology)
			if effectiveRouteGateway.IsValid() {
				updatedConfiguration.RouteGateway = effectiveRouteGateway
			} else {
				c.warnPushedOptionParseError("route-gateway", options.routeGatewayFilterValue(), errInvalidPushedRouteGateway)
			}
		}
		filteredRoutes := c.filterPushedRouteValues("route", options.routesByFamily(true))
		filteredRouteIPv6 := c.filterPushedRouteValues("route-ipv6", options.routesByFamily(false))
		updatedConfiguration.IPv4Routes = appendUniqueTunnelRoutes(updatedConfiguration.IPv4Routes, pushedTunnelRoutes(filteredRoutes, updatedConfiguration.RouteMetric))
		updatedConfiguration.IPv6Routes = appendUniqueTunnelRoutes(updatedConfiguration.IPv6Routes, pushedTunnelRoutes(filteredRouteIPv6, updatedConfiguration.RouteMetric))
		// OpenVPN 2.6 init_route and init_route_ipv6 resolve omitted gateways only
		// after route-gateway and pulled ifconfig endpoints are available.
		ipv4RouteGateway := updatedConfiguration.RouteGateway
		if !ipv4RouteGateway.Is4() {
			ipv4RouteGateway = updatedConfiguration.VPNGateway
		}
		fillTunnelRouteGateways(updatedConfiguration.IPv4Routes, ipv4RouteGateway)
		fillTunnelRouteGateways(updatedConfiguration.IPv6Routes, updatedConfiguration.VPNGatewayIPv6)
		if !updatedConfiguration.RedirectGateway && options.RedirectGateway &&
			c.allowPulledOption("redirect-gateway", strings.Join(options.RedirectGatewayFlags, " ")) {
			updatedConfiguration.RedirectGateway = options.RedirectGateway
			updatedConfiguration.RedirectGatewayFlags = slices.Clone(options.RedirectGatewayFlags)
		}
		if !updatedConfiguration.RedirectPrivate && options.RedirectPrivate &&
			c.allowPulledOption("redirect-private", "") {
			updatedConfiguration.RedirectPrivate = true
		}
	} else {
		fillTunnelRouteGateways(updatedConfiguration.IPv4Routes, updatedConfiguration.VPNGateway)
		fillTunnelRouteGateways(updatedConfiguration.IPv6Routes, updatedConfiguration.VPNGatewayIPv6)
	}
	c.tunnel.configuration = updatedConfiguration
	if isInitialPulledOptions {
		c.maybeReconfigureDataFramingFromPushedOptions(options)
	}
	configurationSnapshot := cloneTunnelConfiguration(c.tunnel.configuration)
	eventQueued := false
	if !deferInitialTunnelEvent {
		eventQueued = c.enqueueTunnelConfigurationEventLocked(TunnelConfigurationEvent{
			Reason:        eventReason,
			Configuration: configurationSnapshot,
		})
	}
	c.tunnel.access.Unlock()
	if eventQueued {
		c.signalTunnelConfigurationEvent()
	}
}

func (c *Client) setInitialTunnelEventDeferred(deferred bool) {
	c.tunnel.access.Lock()
	c.tunnel.deferInitialEvent = deferred
	c.tunnel.access.Unlock()
}

func (c *Client) clearAuthToken() bool {
	interactiveUsername := c.interactiveUsername()
	c.tunnel.access.Lock()
	tokenConfiguration := TunnelConfiguration{
		AuthToken:     c.tunnel.authToken,
		AuthTokenUser: c.tunnel.authTokenUser,
	}
	_, _, tokenDefined := resolveAuthTokenCredentials(c.options, tokenConfiguration, interactiveUsername)
	c.tunnel.authToken = ""
	c.tunnel.authTokenUser = ""
	c.tunnel.configuration.AuthToken = ""
	c.tunnel.configuration.AuthTokenUser = ""
	c.tunnel.access.Unlock()
	return tokenDefined
}

func (c *Client) maybeReconfigureDataFramingFromPushedOptions(options pushedOptions) {
	pushedCompression := strings.TrimSpace(options.Compression)
	pushedCompressionLZO := strings.TrimSpace(options.CompressionLZO)
	if pushedCompression == "" && pushedCompressionLZO == "" {
		return
	}
	// Upstream check_compression_settings_valid (comp.c) rejects
	// non-stub pushed compression under --allow-compression no.
	if c.dataPlane.allowCompressionPolicy == allowCompressionStubOnly && !compressionFramingIsStub(pushedCompression, pushedCompressionLZO) {
		rejectionParts := make([]string, 0, 2)
		if pushedCompression != "" {
			rejectionParts = append(rejectionParts, "compress "+pushedCompression)
		}
		if pushedCompressionLZO != "" {
			rejectionParts = append(rejectionParts, "comp-lzo "+pushedCompressionLZO)
		}
		c.tunnel.compressionPushRejection = strings.Join(rejectionParts, "; ")
		return
	}
	effectiveCompression := c.options.DataChannel.Compression
	if pushedCompression != "" && c.allowPulledOption("compress", pushedCompression) {
		effectiveCompression = pushedCompression
	}
	effectiveCompressionLZO := c.options.DataChannel.CompressionLZO
	if pushedCompressionLZO != "" && c.allowPulledOption("comp-lzo", pushedCompressionLZO) {
		effectiveCompressionLZO = pushedCompressionLZO
	}
	if effectiveCompression == c.options.DataChannel.Compression &&
		effectiveCompressionLZO == c.options.DataChannel.CompressionLZO {
		return
	}
	if validateCompressionOptions(effectiveCompression, effectiveCompressionLZO) != nil {
		return
	}
	syntheticOptions := c.options
	syntheticOptions.DataChannel.Compression = effectiveCompression
	syntheticOptions.DataChannel.CompressionLZO = effectiveCompressionLZO
	c.dataPlane.framing.Store(newDataChannelFraming(syntheticOptions, c.dataPlane.allowCompressionPolicy))
}

func (c *Client) warnPushedOptionParseError(optionName string, optionValue string, err error) {
	if err == nil || c.options.Logger == nil {
		return
	}
	c.options.Logger.WarnContext(c.options.Context, "openvpn: ignored pushed ", optionName, " ", strconv.Quote(optionValue), ": ", err)
}

func (c *Client) warnPushedOptionParseErrors(parseErrors []pushedOptionParseError) {
	for _, parseErr := range parseErrors {
		if c.options.Pull.RouteNoPull && (parseErr.Name == "route" || parseErr.Name == "route-ipv6" || parseErr.Name == "route-gateway") {
			continue
		}
		if c.allowPulledOption(parseErr.Name, parseErr.Value) {
			c.warnPushedOptionParseError(parseErr.Name, parseErr.Value, parseErr.Err)
		}
	}
}

func (c *Client) debugPushedExcludedRoutes(excludedRoutes []pushedExcludedRoute) {
	if len(excludedRoutes) == 0 || c.options.Logger == nil {
		return
	}
	for _, excludedRoute := range excludedRoutes {
		c.options.Logger.DebugContext(c.options.Context, "openvpn: ignored pushed ", excludedRoute.Name, " ", strconv.Quote(excludedRoute.Value), ": route uses net_gateway")
	}
}

func (c *Client) filterPushedLocalAddressValues(optionName string, values []pushedLocalAddress, topology string) []pushedLocalAddress {
	if len(values) == 0 {
		return nil
	}
	filteredValues := make([]pushedLocalAddress, 0, len(values))
	for _, value := range values {
		filterValue := value.Raw
		if filterValue == "" {
			if value.Prefix.Addr().Is4() {
				filterValue = formatPushedIfconfig(value, topology)
			} else {
				filterValue = formatPushedIfconfigIPv6(value)
			}
		}
		if c.allowPulledOption(optionName, filterValue) {
			filteredValues = append(filteredValues, value)
		}
	}
	return filteredValues
}

func (c *Client) filterPushedAddressValues(optionName string, values []pushedAddress) []pushedAddress {
	if len(values) == 0 {
		return nil
	}
	filteredValues := make([]pushedAddress, 0, len(values))
	for _, value := range values {
		filterOptionName := optionName
		if value.OptionName != "" {
			filterOptionName = value.OptionName
		}
		filterValue := value.Raw
		if filterValue == "" && value.Address.IsValid() {
			filterValue = value.Address.String()
		}
		if c.allowPulledOption(filterOptionName, filterValue) {
			filteredValues = append(filteredValues, value)
		}
	}
	return filteredValues
}

func (c *Client) filterPushedRouteValues(optionName string, values []pushedRoute) []pushedRoute {
	if len(values) == 0 {
		return nil
	}
	filteredValues := make([]pushedRoute, 0, len(values))
	for _, value := range values {
		filterValue := value.Raw
		if filterValue == "" {
			filterValue = formatPushedRoute(value)
		}
		if c.allowPulledOption(optionName, filterValue) {
			filteredValues = append(filteredValues, value)
		}
	}
	return filteredValues
}

func appendUniqueStringValues(destination []string, values []string) []string {
	if len(values) == 0 {
		return destination
	}
	mergedValues := slices.Clone(destination)
	seenValues := make(map[string]struct{}, len(mergedValues))
	for _, value := range mergedValues {
		seenValues[value] = struct{}{}
	}
	for _, value := range values {
		_, exists := seenValues[value]
		if exists {
			continue
		}
		seenValues[value] = struct{}{}
		mergedValues = append(mergedValues, value)
	}
	return mergedValues
}

func (c *Client) filterPulledOptionValues(optionName string, values []string) []string {
	if len(values) == 0 {
		return nil
	}
	filteredValues := make([]string, 0, len(values))
	for _, value := range values {
		if c.allowPulledOption(optionName, value) {
			filteredValues = append(filteredValues, value)
		}
	}
	return filteredValues
}

func (c *Client) allowPulledOption(optionName string, optionValue string) bool {
	if len(c.options.Pull.Filters) == 0 {
		return true
	}
	optionLine := optionName
	if optionValue != "" {
		optionLine += " " + optionValue
	}
	for _, filter := range c.options.Pull.Filters {
		if filter.Text == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(optionLine), strings.ToLower(filter.Text)) {
			continue
		}
		switch filter.Action {
		case "ignore":
			return false
		case "reject":
			if c.tunnel.pullFilterRejection == "" {
				c.tunnel.pullFilterRejection = optionLine
			}
			return false
		case "accept":
			return true
		}
	}
	return true
}

func (c *Client) PullFilterRejection() string {
	c.tunnel.access.RLock()
	defer c.tunnel.access.RUnlock()
	return c.tunnel.pullFilterRejection
}

func (c *Client) CompressionPushRejection() string {
	c.tunnel.access.RLock()
	defer c.tunnel.access.RUnlock()
	return c.tunnel.compressionPushRejection
}
