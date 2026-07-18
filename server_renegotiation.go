package openvpn

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

func (s *tlsServerSession) configureRenegotiation() {
	s.renegotiationAccess.Lock()
	defer s.renegotiationAccess.Unlock()
	s.renegotiationBudget = newDataRenegotiationBudget(
		s.selectedCipher,
		0,
		0,
	)
	s.renegotiationInterval = s.server.parent.options.Timing.RenegotiationInterval
	jitteredDuration := applyServerRenegotiationJitter(s.renegotiationInterval)
	if jitteredDuration > 0 {
		s.renegotiationDeadline = time.Now().Add(jitteredDuration)
	}
}

func (s *tlsServerSession) noteRenegotiated() {
	s.renegotiationAccess.Lock()
	defer s.renegotiationAccess.Unlock()
	s.renegotiationBudget.reset()
	jitteredDuration := applyServerRenegotiationJitter(s.renegotiationInterval)
	if jitteredDuration > 0 {
		s.renegotiationDeadline = time.Now().Add(jitteredDuration)
	}
}

// Upstream tls_post_encrypt/tls_pre_decrypt (ssl.c) count inbound and
// outbound bytes against the same renegotiation budget.
func (s *tlsServerSession) consumeRenegotiationBudget(packetID uint32, payloadBytes int) error {
	s.renegotiationAccess.Lock()
	budgetErr := s.renegotiationBudget.consume(packetID, payloadBytes)
	s.renegotiationAccess.Unlock()
	if budgetErr != nil {
		s.requestSoftReset()
	}
	return nil
}

// Upstream should_trigger_renegotiation/key_state_soft_reset (ssl.c).
func (s *tlsServerSession) runRenegotiationLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.renegotiationAccess.Lock()
		deadline := s.renegotiationDeadline
		s.renegotiationAccess.Unlock()
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			s.requestSoftReset()
		}
	}
}

// Upstream key_state_soft_reset (ssl.c) negotiates a new key_id while
// the current key remains active.
func (s *tlsServerSession) requestSoftReset() {
	s.renegotiationAccess.Lock()
	if s.renegotiationInProgress {
		s.renegotiationAccess.Unlock()
		return
	}
	s.renegotiationInProgress = true
	s.renegotiationAccess.Unlock()
	go func() {
		_ = s.triggerSoftReset()
		s.renegotiationAccess.Lock()
		s.renegotiationInProgress = false
		s.renegotiationAccess.Unlock()
	}()
}

// Upstream do_init_crypto_tls (init.c) applies server-only reneg-sec jitter.
func applyServerRenegotiationJitter(renegotiationDuration time.Duration) time.Duration {
	if renegotiationDuration == 0 {
		return 0
	}
	jitterRange := renegotiationDuration / 10
	if jitterRange < time.Second {
		return renegotiationDuration
	}
	var randomByteBuffer [4]byte
	_, readErr := rand.Read(randomByteBuffer[:])
	if readErr != nil {
		return renegotiationDuration
	}
	jitter := time.Duration(binary.BigEndian.Uint32(randomByteBuffer[:])%uint32(jitterRange/time.Second)) * time.Second
	return renegotiationDuration - jitter
}

// Upstream tls_process reads the client key-method message before the
// server reply during soft-reset renegotiation.
func (s *tlsServerSession) runRenegotiation(channel *tlsControlChannel, initiator bool) (dataCodec, error) {
	_ = initiator
	tlsConnection := tls.Server(channel, s.server.tlsConfiguration)
	deadline := time.Now().Add(s.server.parent.options.Timing.HandWindow)
	deadlineErr := tlsConnection.SetDeadline(deadline)
	if deadlineErr != nil {
		return nil, deadlineErr
	}
	handshakeErr := tlsConnection.Handshake()
	if handshakeErr != nil {
		return nil, handshakeErr
	}
	channel.setTLSConnection(tlsConnection)
	certificateIdentityErr := s.verifyLockedCertificateIdentity(tlsConnection)
	if certificateIdentityErr != nil {
		return nil, certificateIdentityErr
	}
	clientKeyMethodRecord, err := readTLSControlRecord(tlsConnection, time.Until(deadline))
	if err != nil {
		return nil, err
	}
	clientMessage, err := parseTLSKeyMethod2Payload(clientKeyMethodRecord, false)
	if err != nil {
		return nil, err
	}
	verifyUserPassErr := s.verifyUserPass(s.sessionContext, clientMessage)
	if verifyUserPassErr != nil {
		_, writeErr := tlsConnection.Write(tlsControlStringPayload(buildAuthFailedPayload("invalid credentials")))
		if writeErr != nil {
			return nil, writeErr
		}
		channel.waitForReliableDelivery(serverScheduledExitInterval)
		return nil, verifyUserPassErr
	}
	serverKeySource, err := generateTLSKeyMethodKeySource(false)
	if err != nil {
		return nil, err
	}
	serverKeyMethodPayload, err := buildTLSKeyMethod2Payload(true, tlsKeyMethodMessage{
		OptionsString: s.localOptionsString,
		PeerInfo:      buildTLSServerPeerInfo(s.server.parent.options),
		KeySource:     serverKeySource,
	})
	if err != nil {
		return nil, err
	}
	remoteSessionID, hasRemoteSessionID := s.sessionManager.RemoteSessionID()
	if !hasRemoteSessionID {
		return nil, E.New("missing remote session id for renegotiation")
	}
	keyMaterial, err := deriveRenegotiatedKeyMaterial(
		tlsConnection,
		peerSupportsIVProtoFlag(clientMessage.PeerInfo, tlsIVProtoTLSKeyExport),
		clientMessage.KeySource,
		serverKeySource,
		s.sessionManager.LocalSessionID(),
		remoteSessionID,
		true,
	)
	if err != nil {
		return nil, err
	}
	newCodec, err := newTLSDataCodec(keyMaterial, true, s.selectedCipher, s.selectedAuth, 0)
	if err != nil {
		return nil, err
	}
	s.stageNegotiatedReceiveKey(channel.sessionManager.CurrentKeyID(), newCodec)
	_, writeErr := tlsConnection.Write(serverKeyMethodPayload)
	if writeErr != nil {
		return newCodec, writeErr
	}
	if !channel.waitForReliableDelivery(time.Until(deadline)) {
		return newCodec, ErrHandshakeTimeout
	}
	_ = tlsConnection.SetDeadline(time.Time{})
	return newCodec, nil
}
