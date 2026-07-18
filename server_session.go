package openvpn

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-openvpn/proto"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

const serverScheduledExitInterval = 5 * time.Second

type tlsServerSession struct {
	*tlsPeerSession
	server              *tlsServer
	peerAddress         string
	selectedCipher      string
	selectedAuth        string
	authFailed          bool
	authFailedReason    string
	sessionContext      context.Context
	cancelSession       context.CancelFunc
	ifconfigInet4       netip.Addr
	ifconfigPeer4       netip.Addr
	ifconfigInet6       netip.Addr
	serverPeerID        uint32
	peerIDAssigned      bool
	resourceReservation *serverResourceReservation
	closeRequestOnce    sync.Once
	closeRequestErr     error

	renegotiationAccess          sync.Mutex
	renegotiationBudget          dataRenegotiationBudget
	renegotiationInterval        time.Duration
	renegotiationDeadline        time.Time
	renegotiationInProgress      bool
	authenticatedUsername        string
	authenticatedUsernameSet     bool
	handshakeDeadline            time.Time
	clientCertificateIdentity    *tlsClientCertificateIdentity
	clientCertificateIdentitySet bool
	authenticatedIdentity        string
	connected                    bool
	finishOnce                   sync.Once
	finishDone                   chan struct{}
}

func (s *tlsServer) newSession(packetConnection proto.PacketConnection, reservation *serverResourceReservation) *tlsServerSession {
	sessionContext, cancelSession := context.WithCancel(s.loopContext)
	session := &tlsServerSession{
		tlsPeerSession: &tlsPeerSession{
			role:                    tlsRoleServer,
			packetConnection:        packetConnection,
			dataTransportHeaderSize: dataTransportHeaderSize(s.parent.protocol),
		},
		server:              s,
		sessionContext:      sessionContext,
		cancelSession:       cancelSession,
		resourceReservation: reservation,
		handshakeDeadline:   time.Now().Add(s.parent.options.Timing.HandWindow),
		finishDone:          make(chan struct{}),
	}
	session.roleCallbacks = tlsRoleCallbacks{
		// Upstream generate_key_expansion orders the client session ID before the server session ID.
		deriveKeyMaterial: func(peerSession *tlsPeerSession) ([]byte, error) {
			if peerSupportsIVProtoFlag(peerSession.peerInfo, tlsIVProtoTLSKeyExport) {
				connectionState := peerSession.tlsConnection.ConnectionState()
				return connectionState.ExportKeyingMaterial("EXPORTER-OpenVPN-datakeys", nil, tlsPRFKeyMaterialLength)
			}
			err := checkTLSKeySourcesComplete(peerSession)
			if err != nil {
				return nil, err
			}
			remoteSessionID, hasRemoteSessionID := peerSession.sessionManager.RemoteSessionID()
			if !hasRemoteSessionID {
				return nil, E.New("missing remote session id for PRF derivation")
			}
			return deriveTLSKeyMaterialPRF(
				peerSession.clientKeySource.PreMaster,
				peerSession.clientKeySource.Random1,
				peerSession.serverKeySource.Random1,
				peerSession.clientKeySource.Random2,
				peerSession.serverKeySource.Random2,
				remoteSessionID,
				peerSession.sessionManager.LocalSessionID(),
			), nil
		},
		renegotiate: func(_ *tlsPeerSession, channel *tlsControlChannel, initiator bool) (dataCodec, error) {
			return session.runRenegotiation(channel, initiator)
		},
		onRenegotiated: func(_ *tlsPeerSession) {
			session.noteRenegotiated()
		},
	}
	session.hooks = tlsPeerHooks{
		outgoingDataPayloads: func(payloads [][]byte, _ dataCodec, _ int) ([][][]byte, error) {
			outgoingPayloads := make([][][]byte, len(payloads))
			for i, payload := range payloads {
				outgoingPayloads[i] = [][]byte{append([]byte{}, payload...)}
			}
			return outgoingPayloads, nil
		},
		outgoingDataBuffers: func(payloads []*buf.Buffer, _ dataCodec, _ int) ([][]*buf.Buffer, error) {
			outgoingPayloads := make([][]*buf.Buffer, len(payloads))
			payloadBatch := make([]*buf.Buffer, len(payloads))
			for i, payload := range payloads {
				payloadBatch[i] = payload
				outgoingPayloads[i] = payloadBatch[i : i+1]
			}
			return outgoingPayloads, nil
		},
		deliverIncomingPayloads: func(payloads [][]byte, _ dataCodec, _ int) {
			session.deliverIncomingPayloads(payloads)
		},
		deliverIncomingBuffers: func(payloads []*buf.Buffer, _ dataCodec, _ int) {
			session.deliverIncomingBuffers(payloads)
		},
		incomingPacketHeadroom: s.parent.options.DataChannel.PacketHeadroom,
		sessionTerminated: func(_ error) {
			_ = session.Close()
		},
		logDroppedIncomingPacket: s.parent.incomingPacketDropLog.Log,
	}
	return session
}

func (s *tlsServerSession) Close() error {
	s.closeRequestOnce.Do(func() {
		s.tlsPeerSession.markClosing()
		if s.cancelSession != nil {
			s.cancelSession()
		}
		if s.packetConnection != nil {
			s.closeRequestErr = s.packetConnection.Close()
		}
	})
	return s.closeRequestErr
}

func (s *tlsServerSession) finish() {
	s.finishOnce.Do(func() {
		_ = s.Close()
		_ = s.tlsPeerSession.Close()
		close(s.finishDone)
	})
}

func (s *tlsServerSession) runWithClientReset(clientResetPacket *proto.Packet, protection tlsControlProtection) error {
	defer s.Close()
	defer s.releaseTunnelAddress()
	s.protection = protection
	var err error
	s.sessionManager, err = proto.NewSessionManager()
	if err != nil {
		return err
	}
	s.sessionManager.SetRemoteSessionID(clientResetPacket.LocalSessionID)
	if _, isUDP := s.packetConnection.(*udpPeerPacketConnection); isUDP {
		s.setAuthenticatedDataPacketObserver(func() bool {
			return s.server.commitAuthenticatedUDPAddress(s)
		})
	}
	serverResetPacket, err := s.sessionManager.NewHardResetServerV2Packet([]proto.PacketID{clientResetPacket.ID})
	if err != nil {
		return err
	}
	err = s.writeHandshakePacket(serverResetPacket)
	if err != nil {
		return err
	}
	return s.runTLSHandshake(nil)
}

func (s *tlsServerSession) runWithCookieResponse(cookieResponse *proto.Packet, protection tlsControlProtection, serverSessionID proto.SessionID) error {
	defer s.Close()
	defer s.releaseTunnelAddress()
	if cookieResponse == nil {
		return E.New("missing UDP cookie response")
	}
	s.protection = protection
	s.sessionManager = proto.NewSessionManagerWithLocalID(serverSessionID)
	s.sessionManager.SetRemoteSessionID(cookieResponse.LocalSessionID)
	s.setAuthenticatedDataPacketObserver(func() bool {
		return s.server.commitAuthenticatedUDPAddress(s)
	})
	return s.runTLSHandshake(cookieResponse)
}

func (s *tlsServerSession) runTLSHandshake(initialControlPacket *proto.Packet) error {
	controlChannel := newTLSControlChannel(
		s.packetConnection,
		s.sessionManager,
		s.protection,
		s.handleIncomingDataPackets,
		s.handleIncomingHardReset,
		s.handleIncomingSoftReset,
	)
	if initialControlPacket != nil && !controlChannel.processIncomingControlPacket(initialControlPacket) {
		return net.ErrClosed
	}
	tlsConnection := tls.Server(controlChannel, s.server.tlsConfiguration)
	if !s.installInitialControlChannel(controlChannel, tlsConnection) {
		return net.ErrClosed
	}
	if !time.Now().Before(s.handshakeDeadline) {
		return ErrHandshakeTimeout
	}
	err := tlsConnection.SetDeadline(s.handshakeDeadline)
	if err != nil {
		return err
	}
	err = tlsConnection.Handshake()
	if err != nil {
		return err
	}
	s.lockInitialCertificateIdentity(tlsConnection)
	_ = tlsConnection.SetDeadline(time.Time{})

	remainingHandshakeWindow := time.Until(s.handshakeDeadline)
	if remainingHandshakeWindow <= 0 {
		return ErrHandshakeTimeout
	}
	clientKeyMethodRecord, err := readTLSControlRecord(s.tlsConnection, remainingHandshakeWindow)
	if err != nil {
		return err
	}
	clientMessage, err := parseTLSKeyMethod2Payload(clientKeyMethodRecord, false)
	if err != nil {
		return err
	}
	s.clientKeySource = clientMessage.KeySource
	s.peerInfo = clientMessage.PeerInfo
	if peerSupportsIVProtoFlag(clientMessage.PeerInfo, tlsIVProtoDataV2) {
		err = s.server.enablePeerID(s)
		if err != nil {
			return err
		}
	}
	verifyUserPassErr := s.verifyUserPass(s.sessionContext, clientMessage)
	if verifyUserPassErr != nil {
		s.authFailed = true
		s.authFailedReason = "invalid credentials"
	}

	selectedCipher, cipherErr := tlsServerCipher(clientMessage.PeerInfo, clientMessage.OptionsString, s.server.parent.options)
	if cipherErr != nil {
		if !s.authFailed {
			s.authFailed = true
			s.authFailedReason = "Data channel cipher negotiation failed (no shared cipher)"
		}
		serverCiphers := tlsAdvertisedDataCiphers(s.server.parent.options.DataChannel.Ciphers)
		selectedCipher = "AES-256-GCM"
		if len(serverCiphers) > 0 {
			selectedCipher = serverCiphers[0]
		}
	}
	s.selectedCipher = selectedCipher
	s.selectedAuth = s.server.parent.options.DataChannel.Auth
	if s.selectedAuth == "" {
		s.selectedAuth = "SHA1"
	}
	serverKeySource, err := generateTLSKeyMethodKeySource(false)
	if err != nil {
		return err
	}
	s.serverKeySource = serverKeySource
	localOptionsString := buildTLSOptionsStringWithMTU(
		s.server.parent.options.Transport.Protocol,
		false,
		s.server.parent.options.TLS.Auth.IsSet(),
		"",
		"",
		s.selectedCipher,
		s.selectedAuth,
		s.server.parent.options.DataChannel.MTU,
	)
	s.localOptionsString = localOptionsString
	serverKeyMethodPayload, err := buildTLSKeyMethod2Payload(true, tlsKeyMethodMessage{
		OptionsString: localOptionsString,
		PeerInfo:      buildTLSServerPeerInfo(s.server.parent.options),
		KeySource:     serverKeySource,
	})
	if err != nil {
		return err
	}
	_, err = s.tlsConnection.Write(serverKeyMethodPayload)
	if err != nil {
		return err
	}
	// OpenVPN completes the key-method exchange even when user/password or
	// cipher authentication has failed.  AUTH_FAILED is a control-channel
	// directive sent in response to the subsequent PUSH_REQUEST; sending it in
	// place of this key-method record makes an OpenVPN client parse the leading
	// 'A' as key-method flags and abort with "Unknown key_method/flags".
	if s.authFailed {
		return s.runControlLoop()
	}

	keyMaterial, err := s.roleCallbacks.deriveKeyMaterial(s.tlsPeerSession)
	if err != nil {
		return err
	}
	initialCodec, err := newTLSDataCodec(keyMaterial, true, s.selectedCipher, s.selectedAuth, 0)
	if err != nil {
		return err
	}
	s.configureRenegotiation()
	s.installInitialDataCodec(initialCodec, s.sessionManager.CurrentKeyID())
	err = s.server.registerAuthenticatedIdentity(s)
	if err != nil {
		return err
	}
	s.resourceReservation.establish()
	pinger := &tlsServerPinger{
		session:      s,
		pingInterval: s.server.parent.options.Timing.PingInterval,
		pingRestart:  s.server.parent.options.Timing.PingRestart,
	}
	pingEnabled := pinger.pingInterval > 0 || pinger.pingRestart > 0
	var readActivityObserver func()
	var writeActivityObserver func()
	if pingEnabled {
		readActivityObserver = func() { pinger.markActivity(true, false) }
		writeActivityObserver = func() { pinger.markActivity(false, true) }
		pinger.markActivity(true, true)
		s.controlChannel.setActivityObservers(readActivityObserver, writeActivityObserver)
	}
	s.setDataObservers(
		s.consumeRenegotiationBudget,
		readActivityObserver,
		func(payloadBytes int) { _ = s.consumeRenegotiationBudget(0, payloadBytes) },
		writeActivityObserver,
		nil,
	)
	sessionLoopContext, cancelSessionLoops := context.WithCancel(s.sessionContext)
	defer cancelSessionLoops()
	var sessionLoopWaitGroup sync.WaitGroup
	sessionLoopWaitGroup.Add(1)
	go func() {
		defer sessionLoopWaitGroup.Done()
		s.runRenegotiationLoop(sessionLoopContext)
	}()
	if pingEnabled {
		sessionLoopWaitGroup.Add(1)
		go func() {
			defer sessionLoopWaitGroup.Done()
			pinger.runLoop(sessionLoopContext)
		}()
	}
	controlLoopErr := s.runControlLoop()
	cancelSessionLoops()
	sessionLoopWaitGroup.Wait()
	return controlLoopErr
}

// Upstream should_trigger_renegotiation (ssl.c) tracks per-key
// byte/packet counters and established+renegotiate_seconds.
func (s *tlsServerSession) readClientReset(initialPacket []byte) (*proto.Packet, tlsControlProtection, error) {
	var rawPacket []byte
	var err error
	if len(initialPacket) > 0 {
		rawPacket = append([]byte{}, initialPacket...)
	} else {
		err = s.packetConnection.SetReadDeadline(s.handshakeDeadline)
		if err != nil {
			return nil, tlsControlProtection{}, err
		}
		rawPacket, err = s.packetConnection.ReadPacket()
		if err != nil {
			return nil, tlsControlProtection{}, err
		}
	}
	return s.server.parseInitialResetPacket(rawPacket)
}

func (s *tlsServer) parseInitialResetPacket(rawPacket []byte) (*proto.Packet, tlsControlProtection, error) {
	if len(rawPacket) == 0 {
		return nil, tlsControlProtection{}, E.New("invalid empty tls control packet")
	}
	opcode := proto.Opcode(rawPacket[0] >> 3)
	// Upstream keeps tls-auth/tls-crypt packet-id and replay state local to each key_state.
	protection := tlsControlProtection{
		auth:  s.staticProtection.auth.newSessionCodec(),
		crypt: s.staticProtection.crypt.newSessionCodec(),
	}
	packetBytes := rawPacket
	if len(s.tlsCryptV2Server) > 0 && (opcode == proto.OpcodeControlHardResetClientV3 || opcode == proto.OpcodeControlWKCv1) {
		if len(rawPacket) < 2 {
			return nil, tlsControlProtection{}, E.New("invalid tls-crypt-v2 packet")
		}
		wrappedKeyLength := int(binary.BigEndian.Uint16(rawPacket[len(rawPacket)-2:]))
		if wrappedKeyLength <= 0 || wrappedKeyLength > len(rawPacket) {
			return nil, tlsControlProtection{}, E.New("invalid tls-crypt-v2 wrapped key")
		}
		wrappedClientKey := rawPacket[len(rawPacket)-wrappedKeyLength:]
		clientKeyMaterial, err := unwrapTLSCryptV2ClientKey(wrappedClientKey, s.tlsCryptV2Server)
		if err != nil {
			return nil, tlsControlProtection{}, err
		}
		protection.crypt, err = newControlCryptCodecFromMaterial(clientKeyMaterial, tlsCryptKeyDirectionNormal)
		if err != nil {
			return nil, tlsControlProtection{}, err
		}
		packetBytes = rawPacket[:len(rawPacket)-wrappedKeyLength]
	}
	if protection.crypt != nil {
		decodedPacket, decoded := protection.crypt.decodeControlPacket(packetBytes)
		if !decoded {
			return nil, tlsControlProtection{}, E.New("invalid tls-crypt packet")
		}
		packetBytes = decodedPacket
	} else if protection.auth != nil {
		decodedPacket, decoded := protection.auth.decodeControlPacket(packetBytes)
		if !decoded {
			return nil, tlsControlProtection{}, E.New("invalid tls-auth packet")
		}
		packetBytes = decodedPacket
	}
	packet, err := proto.ParsePacket(packetBytes)
	if err != nil {
		return nil, tlsControlProtection{}, err
	}
	err = validateInitialClientReset(packet)
	if err != nil {
		return nil, tlsControlProtection{}, err
	}
	return packet, protection, nil
}

func validateInitialClientReset(packet *proto.Packet) error {
	if packet == nil || packet.KeyID != 0 {
		return E.New("invalid initial OpenVPN client reset key-id")
	}
	if packet.Opcode != proto.OpcodeControlHardResetClientV2 && packet.Opcode != proto.OpcodeControlHardResetClientV3 {
		return E.New("invalid initial OpenVPN client reset opcode")
	}
	if packet.ID != 0 || len(packet.AcknowledgmentIDs) != 0 || len(packet.Payload) != 0 {
		return E.New("invalid initial OpenVPN client reset state")
	}
	return nil
}

func (s *tlsServerSession) runControlLoop() error {
	for {
		controlRecord, err := readTLSControlRecord(s.tlsConnection, time.Second)
		if err != nil {
			if E.IsTimeout(err) {
				if s.server.loopContext != nil {
					select {
					case <-s.server.loopContext.Done():
						return nil
					default:
					}
				}
				continue
			}
			return err
		}
		if classifyTLSControlDirective(controlRecord) == tlsControlDirectiveExit {
			return ErrPeerExit
		}
		controlMessage := normalizeTLSControlMessage(controlRecord)
		if strings.EqualFold(controlMessage, pushRequestPayload) || strings.EqualFold(controlMessage, legacyPullRequestPayload) {
			if s.authFailed {
				_, err = s.tlsConnection.Write(tlsControlStringPayload(buildAuthFailedPayload(s.authFailedReason)))
				if err != nil {
					return err
				}
				s.controlChannel.waitForReliableDelivery(serverScheduledExitInterval)
				return ErrAuthenticationFailed
			}
			err = s.allocateAndRegisterTunnelAddress()
			if err != nil {
				return err
			}
			pushPeerID := s.currentPeerID()
			pushLocalAddressOverride := s.pushLocalAddressIPv4()
			pushLocalAddressIPv6Override := s.pushLocalAddressIPv6()
			var serverIPv4 netip.Addr
			if s.server.parent.ipPool != nil && s.server.parent.ipPool.HasIPv4() {
				serverIPv4 = s.server.parent.ipPool.ServerIPv4()
			}
			pushPayloads, pushErr := buildServerPushReplyPayloadsWithOverrides(s.server.parent.options, s.peerInfo, s.selectedCipher, pushPeerID, pushLocalAddressOverride, pushLocalAddressIPv6Override, serverIPv4)
			if pushErr != nil {
				return pushErr
			}
			for _, payload := range pushPayloads {
				_, err = s.tlsConnection.Write(tlsControlStringPayload(payload))
				if err != nil {
					return err
				}
			}
			if !s.connected {
				s.connected = true
				if s.server.parent.options.Logger != nil {
					logArguments := []any{"peer connected: ", s.peerAddress}
					if s.authenticatedUsernameSet {
						logArguments = append(logArguments, ", user ", strconv.Quote(s.authenticatedUsername))
					}
					if s.ifconfigInet4.IsValid() {
						logArguments = append(logArguments, ", IPv4 ", s.ifconfigInet4)
					}
					if s.ifconfigInet6.IsValid() {
						logArguments = append(logArguments, ", IPv6 ", s.ifconfigInet6)
					}
					s.server.parent.options.Logger.InfoContext(s.server.parent.options.Context, logArguments...)
				}
			}
		}
	}
}

func (s *tlsServerSession) logTermination(err error) {
	logger := s.server.parent.options.Logger
	if logger == nil {
		return
	}
	logContext := s.server.parent.options.Context
	if !s.connected {
		if E.IsMulti(err, ErrAuthenticationFailed) {
			logger.WarnContext(logContext, "authentication rejected for peer ", s.peerAddress)
		}
		return
	}
	if err == nil || E.IsMulti(err, net.ErrClosed, context.Canceled, ErrPeerExit, ErrPeerRestart, ErrServerClosed) {
		logger.InfoContext(logContext, "peer disconnected: ", s.peerAddress)
		return
	}
	logger.WarnContext(logContext, "peer disconnected abnormally: ", s.peerAddress, ": ", err)
}

func (s *tlsServerSession) verifyUserPass(ctx context.Context, message tlsKeyMethodMessage) error {
	authenticator := s.server.parent.options.Authentication.Authenticator
	if authenticator == nil {
		return nil
	}
	err := authenticator(ctx, message.Username, message.Password)
	if err != nil {
		return err
	}
	return s.lockAuthenticatedUsername(message.Username)
}

func (s *tlsServerSession) lockAuthenticatedUsername(username string) error {
	if s.authenticatedUsernameSet {
		if username != s.authenticatedUsername {
			return ErrAuthenticationFailed
		}
		return nil
	}
	s.authenticatedUsername = username
	s.authenticatedUsernameSet = true
	return nil
}

func tlsControlStringPayload(payload []byte) []byte {
	if len(payload) == 0 {
		return []byte{0}
	}
	if payload[len(payload)-1] == 0 {
		return append([]byte{}, payload...)
	}
	terminatedPayload := make([]byte, len(payload)+1)
	copy(terminatedPayload, payload)
	return terminatedPayload
}
