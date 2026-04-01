package openvpn

import (
	"net/netip"
	"strings"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

func (c *tlsClient) pullConfigurationAndCipher() (string, string, error) {
	_, writeErr := c.tlsConnection.Write(append([]byte(pushRequestPayload), 0))
	if writeErr != nil {
		return "", "", writeErr
	}
	selectedCipher := tlsPreferredCipher(c.parent.options)
	selectedAuth := c.parent.options.DataChannel.Auth
	if selectedAuth == "" {
		selectedAuth = "SHA1"
	}
	pushedCipherSeen := false
	var accumulatedPushReplyFields []string
	pushContinuationPending := false
	authenticationPending := false
	deadline := time.Now().Add(c.parent.options.Timing.HandWindow)
	nextPushRequest := time.Now().Add(tlsPushRequestResendInterval)
	for time.Now().Before(deadline) {
		readTimeout := time.Until(deadline)
		if resendTimeout := time.Until(nextPushRequest); resendTimeout < readTimeout {
			readTimeout = resendTimeout
		}
		if readTimeout <= 0 {
			readTimeout = time.Millisecond
		}
		controlRecord, readErr := readTLSControlRecord(c.tlsConnection, readTimeout)
		if readErr != nil {
			cancelErr := c.canceledChallengeError()
			if cancelErr != nil {
				return "", "", cancelErr
			}
			if !E.IsTimeout(readErr) {
				return "", "", readErr
			}
			if !time.Now().Before(nextPushRequest) {
				_, writeErr = c.tlsConnection.Write(append([]byte(pushRequestPayload), 0))
				if writeErr != nil {
					return "", "", writeErr
				}
				nextPushRequest = time.Now().Add(tlsPushRequestResendInterval)
			}
			continue
		}
		switch classifyTLSControlDirective(controlRecord) {
		case tlsControlDirectiveAuthFailed:
			return "", "", c.authFailedError(controlRecord)
		case tlsControlDirectiveAuthPending:
			deadline = authPendingDeadline(c.parent.options, controlRecord)
			authenticationPending = true
			c.parent.updateChallengeDeadline(c, deadline)
			continue
		case tlsControlDirectiveRestart:
			return "", "", ErrServerRestart
		case tlsControlDirectiveHalt:
			return "", "", ErrServerHalt
		case tlsControlDirectiveExit:
			return "", "", ErrServerExit
		case tlsControlDirectiveInfoPre:
			c.handleServerPushedInfo(controlRecord, deadline)
			continue
		case tlsControlDirectiveInfo, tlsControlDirectiveCRResponse:
			continue
		case tlsControlDirectivePushReply:
			accumulatedFields, continuation, decoded := appendPushReplyPayloadSegment(accumulatedPushReplyFields, controlRecord)
			pushReplyPayload := controlRecord
			var decodedPushedOptions pushedOptions
			if decoded {
				accumulatedPushReplyFields = accumulatedFields
				pushContinuationPending = continuation == 2
				if pushContinuationPending {
					continue
				}
				pushReplyPayload = []byte(strings.Join(accumulatedPushReplyFields, ","))
				accumulatedPushReplyFields = nil
				decodedPushedOptions, _, decoded = decodePushReplyPayload(pushReplyPayload, c.remoteTransportAddress())
			} else {
				decodedPushedOptions, continuation, decoded = decodePushReplyPayload(controlRecord, c.remoteTransportAddress())
				pushContinuationPending = continuation == 2
			}
			if !decoded || pushContinuationPending {
				continue
			}
			c.parent.applyPushedOptions(decodedPushedOptions)
			pullFilterRejection := c.parent.PullFilterRejection()
			if pullFilterRejection != "" {
				return "", "", ErrPullFilterRejected
			}
			compressionPushRejection := c.parent.CompressionPushRejection()
			if compressionPushRejection != "" {
				return "", "", ErrCompressionPushRejected
			}
			if decodedPushedOptions.PeerID != nil {
				c.setPeerID(decodedPushedOptions.PeerID)
			}
			if decodedPushedOptions.SelectedCipher != "" {
				selectedCipher = decodedPushedOptions.SelectedCipher
				pushedCipherSeen = true
			} else {
				pushedCipher := parsePushedCipher(pushReplyPayload)
				if pushedCipher != "" {
					selectedCipher = pushedCipher
					pushedCipherSeen = true
				}
			}
			if decodedPushedOptions.SelectedAuth != "" {
				selectedAuth = decodedPushedOptions.SelectedAuth
			}
			if continuation != 2 {
				if !pushedCipherSeen {
					resolvedCipher, err := applyCipherNegotiationFallback(c.parent.options, c.remoteCipherName)
					if err != nil {
						return "", "", err
					}
					selectedCipher = resolvedCipher
				}
				return selectedCipher, selectedAuth, nil
			}
		}
	}
	if authenticationPending {
		return "", "", ErrAuthPendingTimeout
	}
	if pushContinuationPending {
		return "", "", E.Extend(ErrHandshakeTimeout, "incomplete push continuation")
	}
	if !pushedCipherSeen {
		resolvedCipher, err := applyCipherNegotiationFallback(c.parent.options, c.remoteCipherName)
		if err != nil {
			return "", "", err
		}
		selectedCipher = resolvedCipher
	}
	return selectedCipher, selectedAuth, nil
}

func (c *tlsClient) controlMessageLoop() {
	for {
		select {
		case <-c.sessionContext.Done():
			c.finish(nil)
			return
		default:
		}
		controlRecord, err := readTLSControlRecord(c.tlsConnection, time.Second)
		if err != nil {
			if E.IsTimeout(err) {
				continue
			}
			c.finish(err)
			return
		}
		dispatchErr := c.dispatchControlDirective(controlRecord)
		if dispatchErr != nil {
			c.finish(dispatchErr)
			return
		}
	}
}

func (c *tlsClient) remoteTransportAddress() netip.Addr {
	if c.packetConnection != nil {
		remoteAddress := M.SocksaddrFromNet(c.packetConnection.RemoteAddr()).Addr.Unmap()
		if remoteAddress.IsValid() {
			return remoteAddress
		}
	}
	return M.ParseSocksaddr(c.remote.address).Addr.Unmap()
}

// Upstream process_explicit_exit_notification_init (sig.c) sends EXIT over
// the control channel when cc-exit is negotiated.
func (c *tlsClient) sendExplicitExitNotifyIfRequested() {
	if c.parent == nil {
		return
	}
	notifyCount := int(c.parent.options.Transport.ExplicitExitNotify)
	if notifyCount <= 0 {
		return
	}
	if c.controlChannel == nil {
		return
	}
	deadlineErr := c.controlChannel.SetWriteDeadline(time.Now().Add(time.Second))
	if deadlineErr != nil {
		return
	}
	if shouldSendCCExitOverControlChannel(c.parent.TunnelConfiguration()) {
		if c.tlsConnection == nil {
			return
		}
		_, _ = c.tlsConnection.Write(tlsControlChannelExitPayload)
		return
	}
	sendCodec, _ := c.currentSendCodec()
	if sendCodec == nil {
		return
	}
	for retry := 0; retry < notifyCount && retry < 10; retry++ {
		writeErr := c.tryWriteDataPacket(openVPNDataChannelExitNotifyPayload)
		if writeErr != nil {
			return
		}
	}
}

func tlsPreferredCipher(options ClientOptions) string {
	for _, dataCipher := range tlsAdvertisedDataCiphers(options.DataChannel.Ciphers) {
		if dataCipher != "" {
			return dataCipher
		}
	}
	return "AES-256-GCM"
}
