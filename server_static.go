package openvpn

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

type staticKeyServer struct {
	parent         *Server
	client         *Client
	loopContext    context.Context
	cancelLoop     context.CancelFunc
	streamListener net.Listener
	packetListener net.PacketConn
	access         sync.RWMutex
	peerAddress    string
	readLoopDone   chan struct{}
}

func newStaticKeyServer(parent *Server) *staticKeyServer {
	return &staticKeyServer{parent: parent}
}

func (s *staticKeyServer) Start() error {
	s.loopContext, s.cancelLoop = context.WithCancel(s.parent.options.Context)
	remote, err := s.prepareTransport()
	if err != nil {
		s.cancelLoop()
		return err
	}
	client, err := NewClient(ClientOptions{
		Context: s.loopContext,
		Mode:    ModeStaticKey,
		Transport: ClientTransportOptions{
			Remotes:     []Remote{remote},
			Protocol:    s.parent.protocol,
			DialContext: s.dialContext,
		},
		DataChannel: ClientDataChannelOptions{
			MTU:              s.parent.options.DataChannel.MTU,
			MSSFix:           s.parent.options.DataChannel.MSSFix,
			MSSFixDisabled:   s.parent.options.DataChannel.MSSFixDisabled,
			MSSFixMode:       s.parent.options.DataChannel.MSSFixMode,
			Cipher:           s.parent.options.DataChannel.Cipher,
			Auth:             s.parent.options.DataChannel.Auth,
			ReplayWindow:     s.parent.options.DataChannel.ReplayWindow,
			ReplayWindowTime: s.parent.options.DataChannel.ReplayWindowTime,
		},
		Tunnel: ClientTunnelOptions{
			DevType:        "tun",
			Topology:       s.parent.options.Tunnel.Topology,
			LocalAddress:   s.parent.options.Tunnel.LocalAddress,
			VPNGateway:     s.parent.options.Tunnel.VPNGateway,
			VPNGatewayIPv6: s.parent.options.Tunnel.VPNGatewayIPv6,
		},
		Timing: ClientTimingOptions{
			PingInterval: s.parent.options.Timing.PingInterval,
			PingRestart:  s.parent.options.Timing.PingRestart,
		},
		StaticKey:    s.parent.options.StaticKey,
		KeyDirection: s.parent.options.KeyDirection,
		Logger:       s.parent.options.Logger,
	})
	if err != nil {
		s.closeTransport()
		s.cancelLoop()
		return err
	}
	s.client = client
	err = client.Start()
	if err != nil {
		s.closeTransport()
		s.cancelLoop()
		_ = client.Close()
		return err
	}
	s.readLoopDone = make(chan struct{})
	go s.readLoop()
	return nil
}

func (s *staticKeyServer) prepareTransport() (Remote, error) {
	if strings.HasPrefix(s.parent.protocol, "tcp") {
		listener := s.parent.options.Transport.Listener
		if listener == nil {
			var err error
			listener, err = net.Listen(s.parent.listenNetwork, s.parent.options.Transport.ListenAddress)
			if err != nil {
				return Remote{}, err
			}
		}
		s.streamListener = listener
		host, port, err := splitStaticServerAddress(listener.Addr().String())
		if err != nil {
			return Remote{}, err
		}
		return Remote{Host: host, Port: port, Protocol: s.parent.protocol}, nil
	}
	if s.parent.options.Transport.RemoteAddress == "" {
		return Remote{}, E.New("static_key UDP server requires Transport.RemoteAddress")
	}
	remoteNetworkAddress, err := net.ResolveUDPAddr(s.parent.listenNetwork, s.parent.options.Transport.RemoteAddress)
	if err != nil {
		return Remote{}, err
	}
	packetListener := s.parent.options.Transport.PacketConn
	if packetListener == nil {
		packetListener, err = net.ListenPacket(s.parent.listenNetwork, s.parent.options.Transport.ListenAddress)
		if err != nil {
			return Remote{}, err
		}
	}
	s.packetListener = packetListener
	s.setPeerAddress(remoteNetworkAddress.String())
	host, port, err := splitStaticServerAddress(remoteNetworkAddress.String())
	if err != nil {
		return Remote{}, err
	}
	return Remote{Host: host, Port: port, Protocol: s.parent.protocol}, nil
}

func splitStaticServerAddress(address string) (string, uint16, error) {
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	portValue, err := strconv.ParseUint(portString, 10, 16)
	if err != nil || portValue == 0 {
		return "", 0, E.New("invalid static_key peer port")
	}
	if host == "" || net.ParseIP(host) == nil {
		host = "127.0.0.1"
		if strings.Contains(address, "[") {
			host = "::1"
		}
	}
	return host, uint16(portValue), nil
}

func (s *staticKeyServer) dialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	if strings.HasPrefix(s.parent.protocol, "tcp") {
		connection, err := s.streamListener.Accept()
		if err != nil {
			return nil, err
		}
		s.setPeerAddress(connection.RemoteAddr().String())
		return connection, nil
	}
	remoteAddress, err := net.ResolveUDPAddr(s.parent.listenNetwork, s.parent.options.Transport.RemoteAddress)
	if err != nil {
		return nil, err
	}
	return &staticServerPacketConnection{PacketConn: s.packetListener, remoteAddress: remoteAddress}, nil
}

func (s *staticKeyServer) setPeerAddress(peerAddress string) {
	s.access.Lock()
	s.peerAddress = peerAddress
	s.access.Unlock()
	if s.parent.options.Tunnel.VPNGateway.IsValid() {
		s.parent.routes.Register(s.parent.options.Tunnel.VPNGateway, peerAddress, nil)
	}
	if s.parent.options.Tunnel.VPNGatewayIPv6.IsValid() {
		s.parent.routes.Register(s.parent.options.Tunnel.VPNGatewayIPv6, peerAddress, nil)
	}
}

func (s *staticKeyServer) currentPeerAddress() string {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.peerAddress
}

func (s *staticKeyServer) readLoop() {
	defer close(s.readLoopDone)
	for {
		packet, err := s.client.ReadDataPacket(s.loopContext)
		if err != nil {
			return
		}
		peerAddress := s.currentPeerAddress()
		if peerAddress == "" || !s.validSource(packet) {
			continue
		}
		s.parent.pushIncomingDataPackets([]ServerDataPacket{{PeerAddress: peerAddress, Payload: packet}})
	}
}

func (s *staticKeyServer) validSource(packet []byte) bool {
	source, parsed := sourceFromIPPacket(packet)
	if !parsed {
		return false
	}
	if source.Is4() {
		return s.parent.options.Tunnel.VPNGateway.IsValid() && source == s.parent.options.Tunnel.VPNGateway
	}
	if source.Is6() {
		return s.parent.options.Tunnel.VPNGatewayIPv6.IsValid() && source == s.parent.options.Tunnel.VPNGatewayIPv6
	}
	return false
}

func (s *staticKeyServer) WriteDataPackets(peerAddress string, packets [][]byte) error {
	if peerAddress == "" || peerAddress != s.currentPeerAddress() {
		return ErrPeerNotFound
	}
	return s.client.WriteDataPackets(packets)
}

func (s *staticKeyServer) WriteDataPacketBuffers(peerAddress string, packetBuffers []*buf.Buffer) error {
	if peerAddress == "" || peerAddress != s.currentPeerAddress() {
		buf.ReleaseMulti(packetBuffers)
		return ErrPeerNotFound
	}
	return s.client.WriteDataPacketBuffers(packetBuffers)
}

func (s *staticKeyServer) Close() error {
	if s.cancelLoop != nil {
		s.cancelLoop()
	}
	closeErr := s.closeTransport()
	if s.client != nil {
		closeErr = E.Errors(closeErr, s.client.Close())
	}
	if s.readLoopDone != nil {
		<-s.readLoopDone
	}
	return closeErr
}

func (s *staticKeyServer) closeTransport() error {
	var err error
	if s.streamListener != nil {
		err = E.Errors(err, s.streamListener.Close())
		s.streamListener = nil
	}
	if s.packetListener != nil {
		err = E.Errors(err, s.packetListener.Close())
		s.packetListener = nil
	}
	return err
}

type staticServerPacketConnection struct {
	net.PacketConn
	remoteAddress net.Addr
}

func (c *staticServerPacketConnection) Read(buffer []byte) (int, error) {
	for {
		dataLength, source, err := c.PacketConn.ReadFrom(buffer)
		if err != nil {
			return 0, err
		}
		if source.String() == c.remoteAddress.String() {
			return dataLength, nil
		}
	}
}

func (c *staticServerPacketConnection) Write(buffer []byte) (int, error) {
	return c.PacketConn.WriteTo(buffer, c.remoteAddress)
}

func (c *staticServerPacketConnection) RemoteAddr() net.Addr {
	return c.remoteAddress
}
