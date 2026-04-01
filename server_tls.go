package openvpn

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-openvpn/proto"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type tlsServer struct {
	parent              *Server
	tlsConfiguration    *tls.Config
	staticProtection    tlsControlProtection
	tlsCryptV2Server    []byte
	sessionAccess       sync.RWMutex
	sessionByPeer       map[string]*tlsServerSession
	sessionByPeerID     map[uint32]*tlsServerSession
	udpSessionByAddress map[string]*tlsServerSession
	loopContext         context.Context
	cancelLoop          context.CancelFunc
	loopWaitGroup       sync.WaitGroup
	lifecycleAccess     sync.Mutex
	lifecycleState      serverLifecycleState
	closeDone           chan struct{}
	closeErr            error
	streamListener      net.Listener
	packetListener      net.PacketConn
	packetBatchReader   N.PacketBatchReadWaiter
	packetWriter        *udpPacketWriter
	resourcePolicy      *serverResourcePolicy
	peerIDCounter       uint32
	sessionCounter      uint64
	droppedUDPPackets   atomic.Uint64
	sessionIDHMACSigner *sessionIDHMACSigner
}

func newTLSServer(parent *Server) (*tlsServer, error) {
	tlsConfiguration, err := buildTLSServerConfiguration(parent.options)
	if err != nil {
		return nil, err
	}
	staticProtection, tlsCryptV2Server, err := newTLSServerProtection(parent.options)
	if err != nil {
		return nil, err
	}
	sessionIDHMACSignerInstance, err := newSessionIDHMACSigner()
	if err != nil {
		return nil, err
	}
	return &tlsServer{
		parent:              parent,
		tlsConfiguration:    tlsConfiguration,
		staticProtection:    staticProtection,
		tlsCryptV2Server:    tlsCryptV2Server,
		sessionByPeer:       make(map[string]*tlsServerSession),
		sessionByPeerID:     make(map[uint32]*tlsServerSession),
		udpSessionByAddress: make(map[string]*tlsServerSession),
		resourcePolicy:      newServerResourcePolicy(parent.options),
		closeDone:           make(chan struct{}),
		sessionIDHMACSigner: sessionIDHMACSignerInstance,
	}, nil
}

func newTLSServerProtection(options ServerOptions) (tlsControlProtection, []byte, error) {
	switch {
	case options.TLS.CryptV2.IsSet():
		serverKey, err := loadTLSCryptV2ServerKey(options.TLS.CryptV2)
		if err != nil {
			return tlsControlProtection{}, nil, err
		}
		return tlsControlProtection{}, serverKey, nil
	case options.TLS.Crypt.IsSet():
		cryptCodec, err := newControlCryptCodec(options.TLS.Crypt, tlsCryptKeyDirectionNormal)
		if err != nil {
			return tlsControlProtection{}, nil, err
		}
		return tlsControlProtection{crypt: cryptCodec}, nil, nil
	case options.TLS.Auth.IsSet():
		authName := options.DataChannel.Auth
		if authName == "" || authName == "NONE" {
			authName = "SHA1"
		}
		authCodec, err := newControlAuthCodecWithAuth(options.TLS.Auth, options.KeyDirection, authName)
		if err != nil {
			return tlsControlProtection{}, nil, err
		}
		return tlsControlProtection{auth: authCodec}, nil, nil
	default:
		return tlsControlProtection{}, nil, nil
	}
}

func (s *tlsServer) Start() error {
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	switch s.lifecycleState {
	case serverLifecycleRunning:
		return nil
	case serverLifecycleStarting:
		return nil
	case serverLifecycleClosing, serverLifecycleClosed:
		return ErrServerClosed
	}
	s.lifecycleState = serverLifecycleStarting
	s.loopContext, s.cancelLoop = context.WithCancel(s.parent.options.Context)
	err := s.loopContext.Err()
	if err != nil {
		s.resetFailedStartLocked()
		return err
	}
	if strings.HasPrefix(s.parent.protocol, "tcp") {
		streamListener := s.parent.options.Transport.Listener
		if streamListener == nil {
			var streamListenErr error
			streamListener, streamListenErr = net.Listen(s.parent.listenNetwork, s.parent.options.Transport.ListenAddress)
			if streamListenErr != nil {
				s.resetFailedStartLocked()
				return streamListenErr
			}
		}
		if streamListener == nil {
			s.resetFailedStartLocked()
			return ErrMissingListenAddress
		}
		s.streamListener = streamListener
		s.lifecycleState = serverLifecycleRunning
		s.loopWaitGroup.Add(1)
		go s.runStreamAcceptLoop()
		return nil
	}
	packetListener := s.parent.options.Transport.PacketConn
	if packetListener == nil {
		var packetListenErr error
		packetListener, packetListenErr = net.ListenPacket(s.parent.listenNetwork, s.parent.options.Transport.ListenAddress)
		if packetListenErr != nil {
			s.resetFailedStartLocked()
			return packetListenErr
		}
	}
	if packetListener == nil {
		s.resetFailedStartLocked()
		return ErrMissingListenAddress
	}
	s.packetListener = packetListener
	s.packetWriter = &udpPacketWriter{listener: packetListener}
	packetConnection := bufio.NewPacketConn(packetListener)
	s.packetBatchReader, _ = bufio.CreatePacketBatchReadWaiter(packetConnection)
	if s.packetBatchReader != nil {
		s.packetBatchReader.InitializeReadWaiter(N.ReadWaitOptions{
			MTU:       math.MaxUint16,
			BatchSize: dataPacketBatchSize,
		})
	}
	s.packetWriter.batchWriter, _ = bufio.CreatePacketBatchWriter(packetConnection)
	s.lifecycleState = serverLifecycleRunning
	s.loopWaitGroup.Add(1)
	go s.runPacketLoop()
	return nil
}

func (s *tlsServer) resetFailedStartLocked() {
	if s.cancelLoop != nil {
		s.cancelLoop()
	}
	s.loopContext = nil
	s.cancelLoop = nil
	s.lifecycleState = serverLifecycleInitial
}

func (s *tlsServer) Close() error {
	s.lifecycleAccess.Lock()
	switch s.lifecycleState {
	case serverLifecycleClosing:
		closeDone := s.closeDone
		s.lifecycleAccess.Unlock()
		<-closeDone
		s.lifecycleAccess.Lock()
		closeErr := s.closeErr
		s.lifecycleAccess.Unlock()
		return closeErr
	case serverLifecycleClosed:
		closeErr := s.closeErr
		s.lifecycleAccess.Unlock()
		return closeErr
	default:
		s.lifecycleState = serverLifecycleClosing
		s.lifecycleAccess.Unlock()
	}

	if s.cancelLoop != nil {
		s.cancelLoop()
	}
	var closeErr error
	if s.streamListener != nil {
		closeErr = E.Errors(closeErr, s.streamListener.Close())
	}
	if s.packetListener != nil {
		closeErr = E.Errors(closeErr, s.packetListener.Close())
	}
	s.sessionAccess.Lock()
	sessions := make([]*tlsServerSession, 0, len(s.sessionByPeer))
	for _, session := range s.sessionByPeer {
		sessions = append(sessions, session)
	}
	s.sessionAccess.Unlock()
	for _, session := range sessions {
		_ = session.Close()
	}
	s.loopWaitGroup.Wait()

	s.lifecycleAccess.Lock()
	s.closeErr = closeErr
	s.lifecycleState = serverLifecycleClosed
	close(s.closeDone)
	s.lifecycleAccess.Unlock()
	return closeErr
}

func (s *tlsServer) WriteDataPackets(peerAddress string, payloads [][]byte) error {
	if len(payloads) == 0 {
		return nil
	}
	if !s.isRunning() {
		return ErrServerClosed
	}
	session := s.getSession(peerAddress)
	if session == nil {
		return ErrPeerNotFound
	}
	return session.WriteDataPackets(payloads)
}

func (s *tlsServer) WriteDataPacketBuffers(peerAddress string, payloads []*buf.Buffer) error {
	if len(payloads) == 0 {
		return nil
	}
	if !s.isRunning() {
		buf.ReleaseMulti(payloads)
		return ErrServerClosed
	}
	session := s.getSession(peerAddress)
	if session == nil {
		buf.ReleaseMulti(payloads)
		return ErrPeerNotFound
	}
	return session.WriteDataPacketBuffers(payloads)
}

func (s *tlsServer) isRunning() bool {
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	return s.lifecycleState == serverLifecycleRunning
}

func (s *tlsServer) runStreamAcceptLoop() {
	defer s.loopWaitGroup.Done()
	for {
		streamConnection, err := s.streamListener.Accept()
		if err != nil {
			select {
			case <-s.loopContext.Done():
				return
			default:
			}
			if E.IsTimeout(err) {
				continue
			}
			return
		}
		reservation := s.resourcePolicy.reserve(time.Now())
		if reservation == nil {
			_ = streamConnection.Close()
			continue
		}
		if !s.reserveLoopWorker() {
			reservation.release()
			_ = streamConnection.Close()
			return
		}
		go s.runStreamSession(streamConnection, reservation)
	}
}

func (s *tlsServer) reserveLoopWorker() bool {
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	if s.lifecycleState != serverLifecycleRunning {
		return false
	}
	s.loopWaitGroup.Add(1)
	return true
}

func (s *tlsServer) runStreamSession(streamConnection net.Conn, reservation *serverResourceReservation) {
	defer s.loopWaitGroup.Done()
	defer reservation.release()
	packetConnection, err := proto.NewPacketConnection(streamConnection, s.parent.protocol)
	if err != nil {
		_ = streamConnection.Close()
		return
	}
	peerAddress := streamConnection.RemoteAddr().String()
	session := s.newSession(packetConnection, reservation)
	defer session.finish()
	err = s.registerSession(peerAddress, session, nil)
	if err != nil {
		return
	}
	defer s.unregisterSession(session)
	clientResetPacket, protection, err := session.readClientReset(nil)
	if err != nil {
		return
	}
	_ = session.runWithClientReset(clientResetPacket, protection)
}

func (s *tlsServer) runPacketLoop() {
	defer s.loopWaitGroup.Done()
	readBuffer := make([]byte, math.MaxUint16)
	for {
		select {
		case <-s.loopContext.Done():
			return
		default:
		}
		err := s.packetListener.SetReadDeadline(time.Now().Add(time.Second))
		if err != nil {
			return
		}
		var rawPacketBuffers []*buf.Buffer
		var remoteAddresses []net.Addr
		var readErr error
		if s.packetBatchReader != nil {
			var destinations []M.Socksaddr
			rawPacketBuffers, destinations, readErr = s.packetBatchReader.WaitReadPackets()
			if len(rawPacketBuffers) != len(destinations) {
				buf.ReleaseMulti(rawPacketBuffers)
				return
			}
			remoteAddresses = make([]net.Addr, len(destinations))
			for i, destination := range destinations {
				remoteAddresses[i] = destination.UDPAddr()
			}
		} else {
			var readCount int
			var remoteAddress net.Addr
			readCount, remoteAddress, readErr = s.packetListener.ReadFrom(readBuffer)
			if readCount > 0 {
				rawPacket := append([]byte{}, readBuffer[:readCount]...)
				rawPacketBuffers = []*buf.Buffer{buf.As(rawPacket)}
				remoteAddresses = []net.Addr{remoteAddress}
			}
		}
		peerAddresses := make([]string, len(remoteAddresses))
		for i, remoteAddress := range remoteAddresses {
			peerAddresses[i] = remoteAddress.String()
		}
		candidateSessions := s.findUDPSessions(rawPacketBuffers, peerAddresses)
		sessionsChanged := false
		queuedPackets := make(map[*udpPeerPacketConnection][]udpPeerPacket)
		queuedPacketConnections := make([]*udpPeerPacketConnection, 0, len(rawPacketBuffers))
		for rawPacketIndex, rawPacketBuffer := range rawPacketBuffers {
			rawPacket := rawPacketBuffer.Bytes()
			remoteAddress := remoteAddresses[rawPacketIndex]
			peerAddress := peerAddresses[rawPacketIndex]
			session := candidateSessions[rawPacketIndex]
			if session == nil && sessionsChanged {
				session = s.findUDPSession(rawPacket, peerAddress)
			}
			if session == nil {
				if !isPossibleUDPPreDecryptPacket(rawPacket) {
					continue
				}
				now := time.Now()
				if !s.resourcePolicy.allowInitialPacket(now) {
					continue
				}
				preDecryptResult, parseErr := s.preDecryptUDPPacket(rawPacket, remoteAddress, now)
				if parseErr != nil {
					continue
				}
				if preDecryptResult.verdict == udpPreDecryptChallenge {
					if !s.resourcePolicy.allowInitialChallenge(now) {
						continue
					}
					writeErr := s.packetWriter.writePacketTo(preDecryptResult.challenge, remoteAddress)
					if writeErr != nil {
						s.droppedUDPPackets.Add(1)
					}
					continue
				}
				if preDecryptResult.verdict != udpPreDecryptAccept {
					continue
				}
				reservation := s.resourcePolicy.reserve(now)
				if reservation == nil {
					continue
				}
				peerPacketConnection := &udpPeerPacketConnection{
					writer:          s.packetWriter,
					localAddress:    s.packetWriter.listener.LocalAddr(),
					remoteAddress:   remoteAddress,
					incomingPackets: newDataPacketQueueWithCapacity[udpPeerPacket](256),
					closed:          make(chan struct{}),
				}
				session = s.newSession(peerPacketConnection, reservation)
				registerErr := s.registerSession(peerAddress, session, remoteAddress)
				if registerErr != nil {
					reservation.release()
					_ = peerPacketConnection.Close()
					continue
				}
				if !s.reserveLoopWorker() {
					s.unregisterSession(session)
					reservation.release()
					session.finish()
					continue
				}
				sessionsChanged = true
				go func(runningSession *tlsServerSession, resourceReservation *serverResourceReservation, acceptedPreDecryptResult udpPreDecryptResult) {
					defer s.loopWaitGroup.Done()
					defer resourceReservation.release()
					defer s.unregisterSession(runningSession)
					defer runningSession.finish()
					_ = runningSession.runWithCookieResponse(
						acceptedPreDecryptResult.packet,
						acceptedPreDecryptResult.protection,
						acceptedPreDecryptResult.serverSessionID,
					)
				}(session, reservation, preDecryptResult)
				continue
			}
			udpPacketConnection, ok := session.packetConnection.(*udpPeerPacketConnection)
			if !ok {
				continue
			}
			if _, loaded := queuedPackets[udpPacketConnection]; !loaded {
				queuedPacketConnections = append(queuedPacketConnections, udpPacketConnection)
			}
			queuedPacketBuffer := buf.NewSize(rawPacketBuffer.Len())
			_, _ = queuedPacketBuffer.Write(rawPacket)
			queuedPackets[udpPacketConnection] = append(queuedPackets[udpPacketConnection], udpPeerPacket{
				buffer:        queuedPacketBuffer,
				remoteAddress: remoteAddress,
			})
		}
		for _, packetConnection := range queuedPacketConnections {
			dropped := packetConnection.pushPackets(queuedPackets[packetConnection])
			if dropped > 0 {
				s.droppedUDPPackets.Add(dropped)
			}
		}
		buf.ReleaseMulti(rawPacketBuffers)
		if readErr != nil {
			if E.IsTimeout(readErr) {
				continue
			}
			return
		}
	}
}

func (s *tlsServer) getSession(peerAddress string) *tlsServerSession {
	s.sessionAccess.Lock()
	defer s.sessionAccess.Unlock()
	return s.sessionByPeer[peerAddress]
}

func (s *tlsServer) registerSession(initialPeerAddress string, session *tlsServerSession, udpAddress net.Addr) error {
	if session == nil || initialPeerAddress == "" {
		return ErrPeerNotFound
	}
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	if s.lifecycleState != serverLifecycleRunning {
		return ErrServerClosed
	}
	s.sessionAccess.Lock()
	defer s.sessionAccess.Unlock()
	if udpAddress != nil {
		if existing := s.udpSessionByAddress[udpAddress.String()]; existing != nil && existing != session {
			return ErrServerResourceLimit
		}
	}
	stablePeerAddress := initialPeerAddress
	if existing := s.sessionByPeer[stablePeerAddress]; existing != nil && existing != session {
		s.sessionCounter++
		stablePeerAddress = fmt.Sprintf("%s#session=%d", initialPeerAddress, s.sessionCounter)
		for s.sessionByPeer[stablePeerAddress] != nil {
			s.sessionCounter++
			stablePeerAddress = fmt.Sprintf("%s#session=%d", initialPeerAddress, s.sessionCounter)
		}
	}
	session.peerAddress = stablePeerAddress
	s.sessionByPeer[stablePeerAddress] = session
	if udpAddress != nil {
		s.udpSessionByAddress[udpAddress.String()] = session
	}
	return nil
}

func (s *tlsServer) enablePeerID(session *tlsServerSession) error {
	if session == nil {
		return ErrPeerNotFound
	}
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	if s.lifecycleState != serverLifecycleRunning {
		return ErrServerClosed
	}
	s.sessionAccess.Lock()
	defer s.sessionAccess.Unlock()
	if s.sessionByPeer[session.peerAddress] != session {
		return ErrPeerNotFound
	}
	if session.peerIDAssigned {
		return nil
	}
	peerID, allocated := s.allocatePeerIDLocked()
	if !allocated {
		return ErrServerResourceLimit
	}
	// Upstream accepts peer-id zero and reserves 0xffffff as the disabled sentinel.
	session.serverPeerID = peerID
	session.peerIDAssigned = true
	session.setPeerID(&peerID)
	s.sessionByPeerID[peerID] = session
	return nil
}

func (s *tlsServer) allocatePeerIDLocked() (uint32, bool) {
	limit := uint32(s.resourcePolicy.maxClients)
	if limit == 0 || limit > peerIDMaxValue {
		return 0, false
	}
	for range limit {
		candidate := s.peerIDCounter % limit
		s.peerIDCounter = (candidate + 1) % limit
		if s.sessionByPeerID[candidate] == nil {
			return candidate, true
		}
	}
	return 0, false
}

func (s *tlsServer) unregisterSession(session *tlsServerSession) {
	if session == nil {
		return
	}
	s.sessionAccess.Lock()
	defer s.sessionAccess.Unlock()
	if s.sessionByPeer[session.peerAddress] == session {
		delete(s.sessionByPeer, session.peerAddress)
	}
	if session.peerIDAssigned && s.sessionByPeerID[session.serverPeerID] == session {
		delete(s.sessionByPeerID, session.serverPeerID)
	}
	for address, boundSession := range s.udpSessionByAddress {
		if boundSession == session {
			delete(s.udpSessionByAddress, address)
		}
	}
}

func (s *tlsServer) findUDPSession(rawPacket []byte, peerAddress string) *tlsServerSession {
	peerID, peerIDEnabled := udpDataV2PeerID(rawPacket)
	s.sessionAccess.RLock()
	defer s.sessionAccess.RUnlock()
	if peerIDEnabled {
		// Upstream P_DATA_V2 selects a candidate by peer-id before authenticating a floated source address.
		return s.sessionByPeerID[peerID]
	}
	return s.udpSessionByAddress[peerAddress]
}

func (s *tlsServer) findUDPSessions(rawPacketBuffers []*buf.Buffer, peerAddresses []string) []*tlsServerSession {
	sessions := make([]*tlsServerSession, len(rawPacketBuffers))
	s.sessionAccess.RLock()
	defer s.sessionAccess.RUnlock()
	for i, rawPacketBuffer := range rawPacketBuffers {
		peerID, peerIDEnabled := udpDataV2PeerID(rawPacketBuffer.Bytes())
		if peerIDEnabled {
			sessions[i] = s.sessionByPeerID[peerID]
		} else {
			sessions[i] = s.udpSessionByAddress[peerAddresses[i]]
		}
	}
	return sessions
}

func udpDataV2PeerID(rawPacket []byte) (uint32, bool) {
	if len(rawPacket) < 4 || proto.Opcode(rawPacket[0]>>3) != proto.OpcodeDataV2 {
		return 0, false
	}
	peerID := uint32(rawPacket[1])<<16 | uint32(rawPacket[2])<<8 | uint32(rawPacket[3])
	if peerID == peerIDMaxValue {
		// MAX_PEER_ID is the upstream sentinel which disables peer-id demux and
		// retains legacy real-address lookup.
		return 0, false
	}
	return peerID, true
}

func (s *tlsServer) commitAuthenticatedUDPAddress(session *tlsServerSession) bool {
	udpConnection, ok := session.packetConnection.(*udpPeerPacketConnection)
	if !ok {
		return true
	}
	remoteAddress := udpConnection.authenticatedRemoteAddress()
	if remoteAddress == nil {
		return false
	}
	newAddress := remoteAddress.String()
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	if s.lifecycleState != serverLifecycleRunning {
		return false
	}
	udpConnection.writer.writeAccess.Lock()
	defer udpConnection.writer.writeAccess.Unlock()
	s.sessionAccess.Lock()
	defer s.sessionAccess.Unlock()
	if s.sessionByPeer[session.peerAddress] != session {
		return false
	}
	if session.peerIDAssigned && s.sessionByPeerID[session.serverPeerID] != session {
		return false
	}
	if existing := s.udpSessionByAddress[newAddress]; existing != nil && existing != session {
		return false
	}
	for address, boundSession := range s.udpSessionByAddress {
		if boundSession == session && address != newAddress {
			delete(s.udpSessionByAddress, address)
		}
	}
	s.udpSessionByAddress[newAddress] = session
	udpConnection.setRemoteAddress(remoteAddress)
	return true
}
