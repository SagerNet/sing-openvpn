package openvpn

import "github.com/sagernet/sing/common/buf"

type OutboundQueue interface {
	WriteBuffers(buffers []*buf.Buffer)
	Close() error
}

func (s *Server) RouteOutbound(packet []byte) OutboundQueue {
	destination, parsed := destinationFromIPPacket(packet)
	if !parsed {
		return nil
	}
	return s.routes.Lookup(destination).queue
}
