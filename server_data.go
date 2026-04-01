package openvpn

import (
	"bytes"
	"context"
	"net/netip"

	"github.com/sagernet/sing/common/buf"
)

type ServerDataPacket struct {
	PeerAddress string
	Payload     []byte
}

type ServerDataBuffer struct {
	PeerAddress string
	Buffer      *buf.Buffer
}

type RouteMissError struct {
	Destination netip.Addr
	Packet      []byte
}

func (e *RouteMissError) Error() string {
	if e == nil || !e.Destination.IsValid() {
		return ErrRouteNotFound.Error()
	}
	return ErrRouteNotFound.Error() + ": " + e.Destination.String()
}

func (e *RouteMissError) Unwrap() error {
	return ErrRouteNotFound
}

func (s *Server) DroppedIncomingDataPackets() uint64 {
	return s.droppedIncomingDataPackets.Load()
}

func (s *Server) ReadDataPacket(ctx context.Context) (ServerDataPacket, error) {
	packetBuffer, err := s.ReadDataPacketBuffer(ctx)
	if err != nil {
		return ServerDataPacket{}, err
	}
	payload := append([]byte(nil), packetBuffer.Buffer.Bytes()...)
	packetBuffer.Buffer.Release()
	return ServerDataPacket{
		PeerAddress: packetBuffer.PeerAddress,
		Payload:     payload,
	}, nil
}

func (s *Server) ReadDataPackets(ctx context.Context) ([]ServerDataBuffer, error) {
	return s.readDataPackets(ctx, 0)
}

func (s *Server) ReadDataPacketBuffer(ctx context.Context) (ServerDataBuffer, error) {
	packetBuffers, err := s.readDataPackets(ctx, 1)
	if err != nil {
		return ServerDataBuffer{}, err
	}
	return packetBuffers[0], nil
}

func (s *Server) readDataPackets(ctx context.Context, maxPackets int) ([]ServerDataBuffer, error) {
	loopContext, err := s.activeLoopContext()
	if err != nil {
		return nil, err
	}
	for {
		select {
		case <-loopContext.Done():
			return nil, ErrServerClosed
		default:
		}
		packetBuffers := s.incomingDataPackets.Pop(maxPackets, nil)
		if len(packetBuffers) > 0 {
			return packetBuffers, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-loopContext.Done():
			return nil, ErrServerClosed
		case <-s.incomingDataPackets.Wake():
		}
	}
}

func (s *Server) WriteDataPacket(peerAddress string, packet []byte) error {
	return s.WriteDataPackets(peerAddress, [][]byte{packet})
}

func (s *Server) WriteDataPackets(peerAddress string, packets [][]byte) error {
	if len(packets) == 0 {
		return nil
	}
	err := s.requireRunning()
	if err != nil {
		return err
	}
	return s.tls.WriteDataPackets(peerAddress, packets)
}

func (s *Server) WriteDataPacketByDestination(packet []byte) error {
	routeMisses, err := s.WriteDataPacketsByDestination([][]byte{packet})
	if err != nil {
		return err
	}
	if len(routeMisses) > 0 {
		return routeMisses[0]
	}
	return nil
}

func (s *Server) WriteDataPacketsByDestination(packets [][]byte) ([]*RouteMissError, error) {
	if len(packets) == 0 {
		return nil, nil
	}
	err := s.requireRunning()
	if err != nil {
		return nil, err
	}
	var routeMisses []*RouteMissError
	var routeLookups []peerRouteLookup
	if s.routes != nil {
		routeLookups = s.routes.LookupPackets(packets)
	}
	var currentRoute peerRoute
	currentPackets := make([][]byte, 0, len(packets))
	flushCurrentBatch := func() error {
		if len(currentPackets) == 0 {
			return nil
		}
		var writeErr error
		if currentRoute.session != nil {
			writeErr = currentRoute.session.WriteDataPackets(currentPackets)
		} else {
			writeErr = s.tls.WriteDataPackets(currentRoute.peerAddress, currentPackets)
		}
		currentPackets = currentPackets[:0]
		return writeErr
	}
	for i, packet := range packets {
		var route peerRoute
		var destination netip.Addr
		var found bool
		if routeLookups != nil {
			route = routeLookups[i].route
			destination = routeLookups[i].destination
			found = routeLookups[i].found
		} else {
			destination, _ = destinationFromIPPacket(packet)
		}
		if !found {
			err = flushCurrentBatch()
			if err != nil {
				return routeMisses, err
			}
			packetRouteErr := newRouteMissError(destination, packet)
			routeMiss, isRouteMiss := packetRouteErr.(*RouteMissError)
			if !isRouteMiss {
				return routeMisses, packetRouteErr
			}
			routeMisses = append(routeMisses, routeMiss)
			continue
		}
		if len(currentPackets) > 0 && route != currentRoute {
			err = flushCurrentBatch()
			if err != nil {
				return routeMisses, err
			}
		}
		if len(currentPackets) == 0 {
			currentRoute = route
		}
		currentPackets = append(currentPackets, packet)
	}
	err = flushCurrentBatch()
	return routeMisses, err
}

func (s *Server) WriteDataPacketBuffersByDestination(packetBuffers []*buf.Buffer) ([]*RouteMissError, error) {
	if len(packetBuffers) == 0 {
		return nil, nil
	}
	err := s.requireRunning()
	if err != nil {
		buf.ReleaseMulti(packetBuffers)
		return nil, err
	}
	packets := make([][]byte, len(packetBuffers))
	for i, packetBuffer := range packetBuffers {
		packets[i] = packetBuffer.Bytes()
	}
	var routeMisses []*RouteMissError
	var routeLookups []peerRouteLookup
	if s.routes != nil {
		routeLookups = s.routes.LookupPackets(packets)
	}
	var currentRoute peerRoute
	currentPacketBuffers := make([]*buf.Buffer, 0, len(packetBuffers))
	flushCurrentBatch := func() error {
		if len(currentPacketBuffers) == 0 {
			return nil
		}
		var writeErr error
		if currentRoute.session != nil {
			writeErr = currentRoute.session.WriteDataPacketBuffers(currentPacketBuffers)
		} else {
			writeErr = s.tls.WriteDataPacketBuffers(currentRoute.peerAddress, currentPacketBuffers)
		}
		currentPacketBuffers = nil
		return writeErr
	}
	for i, packetBuffer := range packetBuffers {
		packet := packetBuffer.Bytes()
		var route peerRoute
		var destination netip.Addr
		var found bool
		if routeLookups != nil {
			route = routeLookups[i].route
			destination = routeLookups[i].destination
			found = routeLookups[i].found
		} else {
			destination, _ = destinationFromIPPacket(packet)
		}
		if !found {
			err = flushCurrentBatch()
			if err != nil {
				packetBuffer.Release()
				buf.ReleaseMulti(packetBuffers[i+1:])
				return routeMisses, err
			}
			packetRouteErr := newRouteMissError(destination, packet)
			packetBuffer.Release()
			routeMiss, isRouteMiss := packetRouteErr.(*RouteMissError)
			if !isRouteMiss {
				buf.ReleaseMulti(packetBuffers[i+1:])
				return routeMisses, packetRouteErr
			}
			routeMisses = append(routeMisses, routeMiss)
			continue
		}
		if len(currentPacketBuffers) > 0 && route != currentRoute {
			err = flushCurrentBatch()
			if err != nil {
				packetBuffer.Release()
				buf.ReleaseMulti(packetBuffers[i+1:])
				return routeMisses, err
			}
		}
		if len(currentPacketBuffers) == 0 {
			currentRoute = route
		}
		currentPacketBuffers = append(currentPacketBuffers, packetBuffer)
	}
	err = flushCurrentBatch()
	return routeMisses, err
}

func newRouteMissError(destination netip.Addr, packet []byte) error {
	if !destination.IsValid() {
		return ErrInvalidIPPacket
	}
	return &RouteMissError{
		Destination: destination,
		Packet:      bytes.Clone(packet),
	}
}

func (s *Server) pushIncomingDataPackets(packets []ServerDataPacket) {
	if len(packets) == 0 {
		return
	}
	packetBuffers := make([]ServerDataBuffer, 0, len(packets))
	for _, packet := range packets {
		if packet.PeerAddress == "" || len(packet.Payload) == 0 {
			continue
		}
		packetBuffers = append(packetBuffers, ServerDataBuffer{
			PeerAddress: packet.PeerAddress,
			Buffer:      newDataPacketBuffer(s.options.DataChannel.PacketHeadroom, packet.Payload),
		})
	}
	dropped := s.incomingDataPackets.PushBatch(packetBuffers, func(packetBuffer ServerDataBuffer) {
		if packetBuffer.Buffer != nil {
			packetBuffer.Buffer.Release()
		}
	})
	if dropped > 0 {
		s.droppedIncomingDataPackets.Add(dropped)
	}
}

func (s *Server) pushIncomingDataBuffers(packetBuffers []ServerDataBuffer) {
	if len(packetBuffers) == 0 {
		return
	}
	dropped := s.incomingDataPackets.PushBatch(packetBuffers, func(packetBuffer ServerDataBuffer) {
		if packetBuffer.Buffer != nil {
			packetBuffer.Buffer.Release()
		}
	})
	if dropped > 0 {
		s.droppedIncomingDataPackets.Add(dropped)
	}
}

func (s *Server) prepareServerDataPlane() error {
	if len(s.options.Tunnel.AddressPools) == 0 && len(s.options.Tunnel.LocalAddress) == 0 {
		return nil
	}
	pool, err := newIPPool(s.options.Tunnel.AddressPools, s.options.Tunnel.Topology)
	if err != nil {
		return err
	}
	if pool.HasIPv4() {
		ipv4Prefix, ipv4PrefixLoaded := firstPrefixByFamily(s.options.Tunnel.LocalAddress, true)
		if ipv4PrefixLoaded {
			err = pool.SetServerIPv4(ipv4Prefix.Addr())
			if err != nil {
				return err
			}
		}
	}
	if pool.HasIPv6() {
		ipv6Prefix, ipv6PrefixLoaded := firstPrefixByFamily(s.options.Tunnel.LocalAddress, false)
		if ipv6PrefixLoaded {
			err = pool.SetServerIPv6(ipv6Prefix.Addr())
			if err != nil {
				return err
			}
		}
	}
	s.ipPool = pool
	if s.routes == nil {
		s.routes = newPeerRouteRegistry()
	}
	return nil
}

func firstPrefixByFamily(prefixes []netip.Prefix, ipv4 bool) (netip.Prefix, bool) {
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			continue
		}
		if prefix.Addr().Is4() == ipv4 {
			return prefix, true
		}
	}
	return netip.Prefix{}, false
}

func (s *tlsServerSession) deliverIncomingPayloads(payloads [][]byte) {
	parent := s.server.parent
	packets := make([]ServerDataPacket, 0, len(payloads))
	ownerships := parent.routes.SourcesOwnedBy(payloads, s.tlsPeerSession)
	for i, payload := range payloads {
		if !ownerships[i].owned {
			if parent.options.Logger != nil {
				if ownerships[i].sourceAddress.IsValid() {
					parent.options.Logger.DebugContext(parent.options.Context, "openvpn: bad source address from client ", s.peerAddress, " [", ownerships[i].sourceAddress, "], packet dropped")
				} else {
					parent.options.Logger.DebugContext(parent.options.Context, "openvpn: malformed IP packet from client ", s.peerAddress, ", packet dropped")
				}
			}
			continue
		}
		packets = append(packets, ServerDataPacket{
			PeerAddress: s.peerAddress,
			Payload:     payload,
		})
	}
	parent.pushIncomingDataPackets(packets)
}

func (s *tlsServerSession) deliverIncomingBuffers(payloadBuffers []*buf.Buffer) {
	parent := s.server.parent
	payloads := make([][]byte, len(payloadBuffers))
	for i, payloadBuffer := range payloadBuffers {
		payloads[i] = payloadBuffer.Bytes()
	}
	packetBuffers := make([]ServerDataBuffer, 0, len(payloadBuffers))
	ownerships := parent.routes.SourcesOwnedBy(payloads, s.tlsPeerSession)
	for i, payloadBuffer := range payloadBuffers {
		if !ownerships[i].owned {
			if parent.options.Logger != nil {
				if ownerships[i].sourceAddress.IsValid() {
					parent.options.Logger.DebugContext(parent.options.Context, "openvpn: bad source address from client ", s.peerAddress, " [", ownerships[i].sourceAddress, "], packet dropped")
				} else {
					parent.options.Logger.DebugContext(parent.options.Context, "openvpn: malformed IP packet from client ", s.peerAddress, ", packet dropped")
				}
			}
			payloadBuffer.Release()
			continue
		}
		packetBuffers = append(packetBuffers, ServerDataBuffer{
			PeerAddress: s.peerAddress,
			Buffer:      payloadBuffer,
		})
	}
	parent.pushIncomingDataBuffers(packetBuffers)
}
