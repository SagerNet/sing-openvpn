package openvpn

import "time"

// Upstream reliable_schedule_packet (reliable.c) caps TLS retransmission
// backoff; options_postprocess_mutate (options.c) defaults hand-window.
const (
	tlsHandshakeRetryInitial  = 2 * time.Second
	tlsHandshakeRetryMaximum  = 60 * time.Second
	tlsHandshakeTotalDuration = 60 * time.Second
)

// Upstream check_push_request (forward.c) re-sends PUSH_REQUEST every
// PUSH_REQUEST_INTERVAL seconds until push_request_timeout, which starts at
// hand-window and is replaced by AUTH_PENDING; this resend is also what keeps
// the pending authentication exchange alive.
const tlsPushRequestResendInterval = 5 * time.Second

// Upstream check_ping_restart/check_ping_exit (forward.c).
func shouldExitForPingTimeout(lastInbound time.Time, now time.Time, pingRestart time.Duration, pingExit time.Duration) bool {
	threshold := pingRestart
	if pingExit > 0 && (threshold <= 0 || pingExit < threshold) {
		threshold = pingExit
	}
	if threshold <= 0 || lastInbound.IsZero() {
		return false
	}
	return now.Sub(lastInbound) > threshold
}

// Upstream check_inactivity_timeout (forward.c).
func shouldExitForInactivityTimeout(lastInactivityReset time.Time, now time.Time, inactiveTimeout time.Duration) bool {
	if inactiveTimeout <= 0 {
		return false
	}
	if lastInactivityReset.IsZero() {
		return false
	}
	return now.Sub(lastInactivityReset) >= inactiveTimeout
}
