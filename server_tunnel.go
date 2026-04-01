package openvpn

import "net/netip"

func (s *tlsServerSession) allocateAndRegisterTunnelAddress() error {
	parent := s.server.parent
	if parent.routes == nil || parent.ipPool == nil {
		return nil
	}
	if parent.ipPool.HasIPv4() && !s.ifconfigInet4.IsValid() {
		lease, err := parent.ipPool.AllocateIPv4()
		if err != nil {
			return err
		}
		s.ifconfigInet4 = lease.Client
		s.ifconfigPeer4 = lease.Peer
		parent.routes.Register(lease.Client, s.peerAddress, s.tlsPeerSession)
	}
	if parent.ipPool.HasIPv6() && !s.ifconfigInet6.IsValid() {
		address, err := parent.ipPool.AllocateIPv6()
		if err != nil {
			return err
		}
		s.ifconfigInet6 = address
		parent.routes.Register(address, s.peerAddress, s.tlsPeerSession)
	}
	return nil
}

func (s *tlsServerSession) releaseTunnelAddress() {
	parent := s.server.parent
	if s.ifconfigInet4.IsValid() {
		if parent.routes != nil {
			parent.routes.Unregister(s.ifconfigInet4)
		}
		if parent.ipPool != nil {
			parent.ipPool.Release(s.ifconfigInet4)
		}
		s.ifconfigInet4 = netip.Addr{}
		s.ifconfigPeer4 = netip.Addr{}
	}
	if s.ifconfigInet6.IsValid() {
		if parent.routes != nil {
			parent.routes.Unregister(s.ifconfigInet6)
		}
		if parent.ipPool != nil {
			parent.ipPool.Release(s.ifconfigInet6)
		}
		s.ifconfigInet6 = netip.Addr{}
	}
}

func (s *tlsServerSession) pushLocalAddressIPv4() pushedLocalAddress {
	parent := s.server.parent
	if !s.ifconfigInet4.IsValid() || parent.ipPool == nil || !parent.ipPool.HasIPv4() {
		return pushedLocalAddress{}
	}
	prefix := parent.ipPool.IPv4Prefix()
	topology := parent.ipPool.IPv4Topology()
	switch topology {
	case ipv4TopologySubnet:
		return pushedLocalAddress{Prefix: netip.PrefixFrom(s.ifconfigInet4, prefix.Bits())}
	case ipv4TopologyP2P:
		return pushedLocalAddress{Prefix: netip.PrefixFrom(s.ifconfigInet4, 32), Peer: s.ifconfigPeer4}
	case ipv4TopologyNet30:
		return pushedLocalAddress{Prefix: netip.PrefixFrom(s.ifconfigInet4, 30), Peer: s.ifconfigPeer4}
	default:
		return pushedLocalAddress{}
	}
}

func (s *tlsServerSession) pushLocalAddressIPv6() pushedLocalAddress {
	parent := s.server.parent
	if !s.ifconfigInet6.IsValid() || parent.ipPool == nil || !parent.ipPool.HasIPv6() {
		return pushedLocalAddress{}
	}
	prefix := parent.ipPool.IPv6Prefix()
	return pushedLocalAddress{Prefix: netip.PrefixFrom(s.ifconfigInet6, prefix.Bits()), Peer: parent.ipPool.ServerIPv6()}
}
