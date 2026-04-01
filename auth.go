package openvpn

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	authFailedPayload  = "AUTH_FAILED"
	authPendingPayload = "AUTH_PENDING"
)

// Upstream receive_auth_pending (push.c) replaces the pending-auth expiry:
// the timeout defaults to hand-window, the server may propose one with
// "AUTH_PENDING,timeout <seconds>", and the result is capped at
// max(reneg-sec/2, hand-window).
func authPendingDeadline(options ClientOptions, controlRecord []byte) time.Time {
	handWindow := options.Timing.HandWindow
	renegotiationInterval := options.Timing.RenegotiationInterval
	maximumExtension := max(handWindow, renegotiationInterval/2)
	extension := handWindow
	parsedTimeout, hasTimeout := parseAuthPendingTimeout(controlRecord)
	if hasTimeout {
		extension = time.Duration(parsedTimeout) * time.Second
	}
	extension = min(extension, maximumExtension)
	return time.Now().Add(extension)
}

func (c *Client) sessionCredentials(useActiveAuthToken bool) (string, string) {
	if useActiveAuthToken {
		c.tunnel.access.RLock()
		tokenConfiguration := TunnelConfiguration{
			AuthToken:     c.tunnel.authToken,
			AuthTokenUser: c.tunnel.authTokenUser,
		}
		c.tunnel.access.RUnlock()
		tokenUsername, tokenPassword, tokenDefined := resolveAuthTokenCredentials(c.options, tokenConfiguration, c.interactiveUsername())
		if tokenDefined {
			return c.noteSentCredentials(tokenUsername, tokenPassword, false)
		}
	}
	c.authentication.access.Lock()
	challengeUsername := c.authentication.challengeResponseUsername
	challengePassword := c.authentication.challengeResponsePassword
	c.authentication.challengeResponseUsername = ""
	c.authentication.challengeResponsePassword = ""
	interactiveUsername := c.authentication.interactiveUsername
	interactivePassword := c.authentication.interactivePassword
	interactiveSecret := c.authentication.interactiveSecret
	c.authentication.access.Unlock()
	usedInteractive := false
	username := c.options.Authentication.Username
	if username == "" && interactiveUsername != "" {
		username = interactiveUsername
		usedInteractive = true
	}
	if challengePassword != "" {
		if challengeUsername != "" {
			username = challengeUsername
		}
		return c.noteSentCredentials(username, challengePassword, true)
	}
	password := c.options.Authentication.Password
	if password == "" && interactivePassword != "" {
		password = interactivePassword
		usedInteractive = true
	}
	challengeResponse := interactiveSecret
	if challengeResponse != "" {
		usedInteractive = true
		// Upstream get_user_pass_static_challenge uses SCRV1 for static challenges.
		encodedPassword := base64.StdEncoding.EncodeToString([]byte(password))
		encodedResponse := base64.StdEncoding.EncodeToString([]byte(challengeResponse))
		password = "SCRV1:" + encodedPassword + ":" + encodedResponse
	}
	return c.noteSentCredentials(username, password, usedInteractive)
}

func (c *Client) noteSentCredentials(username string, password string, usedInteractive bool) (string, string) {
	c.authentication.access.Lock()
	c.authentication.sentInteractiveCredentials = usedInteractive
	c.authentication.access.Unlock()
	return username, password
}

func (c *Client) lastSentCredentialsInteractive() bool {
	c.authentication.access.Lock()
	defer c.authentication.access.Unlock()
	return c.authentication.sentInteractiveCredentials
}

func (c *Client) interactiveUsername() string {
	c.authentication.access.Lock()
	defer c.authentication.access.Unlock()
	return c.authentication.interactiveUsername
}

func (c *Client) setInteractiveUserPass(username string, password string) {
	c.authentication.access.Lock()
	c.authentication.interactiveUsername = username
	c.authentication.interactivePassword = password
	c.authentication.access.Unlock()
}

func (c *Client) setInteractiveSecret(secret string) {
	c.authentication.access.Lock()
	c.authentication.interactiveSecret = secret
	c.authentication.access.Unlock()
}

func (c *Client) setChallengeResponseCredentials(username string, password string) {
	c.authentication.access.Lock()
	c.authentication.challengeResponseUsername = username
	c.authentication.challengeResponsePassword = password
	c.authentication.access.Unlock()
}

func (c *Client) clearInteractiveCredentials() {
	c.authentication.access.Lock()
	c.authentication.interactiveUsername = ""
	c.authentication.interactivePassword = ""
	c.authentication.interactiveSecret = ""
	c.authentication.challengeResponseUsername = ""
	c.authentication.challengeResponsePassword = ""
	c.authentication.access.Unlock()
}

func resolveAuthTokenCredentials(options ClientOptions, configuration TunnelConfiguration, interactiveUsername string) (string, string, bool) {
	if configuration.AuthToken == "" {
		return "", "", false
	}
	if configuration.AuthTokenUser != "" {
		username, defined := decodeAuthTokenUsername(configuration.AuthTokenUser)
		if !defined {
			return "", "", false
		}
		return username, configuration.AuthToken, true
	}
	username := options.Authentication.Username
	if username == "" {
		username = interactiveUsername
	}
	if username == "" {
		return "", "", false
	}
	return username, configuration.AuthToken, true
}

func decodeAuthTokenUsername(encodedUsername string) (string, bool) {
	decodedUsername, err := base64.StdEncoding.DecodeString(encodedUsername)
	if err != nil {
		return "", false
	}
	if len(decodedUsername) == 0 {
		return "", false
	}
	nullIndex := bytes.IndexByte(decodedUsername, 0)
	if nullIndex >= 0 {
		decodedUsername = decodedUsername[:nullIndex]
	}
	return string(decodedUsername), true
}

func isAuthFailedPayload(payload []byte) bool {
	normalizedPayload := normalizeControlPayload(payload)
	if normalizedPayload == "" {
		return false
	}
	if strings.EqualFold(normalizedPayload, authFailedPayload) {
		return true
	}
	return strings.HasPrefix(strings.ToUpper(normalizedPayload), authFailedPayload+",")
}

func buildAuthFailedPayload(reason string) []byte {
	trimmedReason := strings.TrimSpace(reason)
	if trimmedReason == "" {
		return []byte(authFailedPayload)
	}
	return []byte(authFailedPayload + "," + trimmedReason)
}

type AuthFailedAdvance int

const (
	AuthFailedAdvanceNextAddress AuthFailedAdvance = iota
	AuthFailedAdvanceNextRemote
	AuthFailedAdvanceStay
)

type AuthFailedTemporaryError struct {
	BackoffSeconds uint32
	Advance        AuthFailedAdvance
	Reason         string
}

func (temporaryError *AuthFailedTemporaryError) Error() string {
	if temporaryError.Reason == "" {
		return ErrAuthenticationFailed.Error() + ": temporary failure"
	}
	return ErrAuthenticationFailed.Error() + ": temporary failure: " + temporaryError.Reason
}

func (temporaryError *AuthFailedTemporaryError) Unwrap() error {
	return ErrAuthenticationFailed
}

type authFailedInfo struct {
	failed         bool
	temporary      bool
	reason         string
	backoffSeconds uint32
	advance        AuthFailedAdvance
}

// Upstream parse_auth_failed_temp parses:
//
//	AUTH_FAILED,TEMP[<flags>]:<reason>
//
// with "backoff <N>" and "advance no|remote|addr" flags.
func parseAuthFailedPayload(payload []byte) authFailedInfo {
	normalized := normalizeControlPayload(payload)
	if normalized == "" {
		return authFailedInfo{}
	}
	if !strings.HasPrefix(strings.ToUpper(normalized), authFailedPayload) {
		return authFailedInfo{}
	}
	suffix := strings.TrimPrefix(normalized, authFailedPayload)
	if suffix == "" {
		return authFailedInfo{failed: true}
	}
	if !strings.HasPrefix(suffix, ",") {
		return authFailedInfo{}
	}
	suffix = strings.TrimPrefix(suffix, ",")
	info := authFailedInfo{failed: true}
	if !strings.HasPrefix(strings.ToUpper(suffix), "TEMP") {
		info.reason = strings.TrimSpace(suffix)
		return info
	}
	info.temporary = true
	suffix = strings.TrimPrefix(suffix, "TEMP")
	if strings.HasPrefix(suffix, "[") {
		closingBracketIndex := strings.Index(suffix, "]")
		if closingBracketIndex >= 0 {
			bracketContent := suffix[1:closingBracketIndex]
			applyAuthFailedTemporaryFlags(&info, bracketContent)
			suffix = suffix[closingBracketIndex+1:]
		}
	}
	suffix = strings.TrimPrefix(suffix, ":")
	info.reason = strings.TrimSpace(suffix)
	return info
}

func applyAuthFailedTemporaryFlags(info *authFailedInfo, bracketContent string) {
	for flagEntry := range strings.SplitSeq(bracketContent, ",") {
		trimmedFlag := strings.TrimSpace(flagEntry)
		if trimmedFlag == "" {
			continue
		}
		keyword, value, hasSpace := strings.Cut(trimmedFlag, " ")
		if !hasSpace {
			continue
		}
		trimmedValue := strings.TrimSpace(value)
		switch strings.ToLower(keyword) {
		case "backoff":
			parsedBackoff, err := strconv.ParseUint(trimmedValue, 10, 32)
			if err == nil {
				info.backoffSeconds = uint32(parsedBackoff)
			}
		case "advance":
			switch strings.ToLower(trimmedValue) {
			case "no":
				info.advance = AuthFailedAdvanceStay
			case "remote":
				info.advance = AuthFailedAdvanceNextRemote
			case "addr":
				info.advance = AuthFailedAdvanceNextAddress
			}
		}
	}
}

func newAuthFailedErrorFromPayload(payload []byte, authRetry string) error {
	challenge, foundChallenge := extractCRV1FromAuthFailed(payload)
	if foundChallenge {
		return &AuthChallengeError{Challenge: challenge}
	}
	info := parseAuthFailedPayload(payload)
	if !info.failed {
		if resolveAuthRetryMode(authRetry) == AuthRetryModeNone {
			return &AuthFailedTerminalError{}
		}
		return ErrAuthenticationFailed
	}
	if info.temporary {
		return &AuthFailedTemporaryError{
			BackoffSeconds: info.backoffSeconds,
			Advance:        info.advance,
			Reason:         info.reason,
		}
	}
	if resolveAuthRetryMode(authRetry) == AuthRetryModeNone {
		return &AuthFailedTerminalError{Reason: info.reason}
	}
	return ErrAuthenticationFailed
}

type AuthTokenAuthenticationFailedError struct {
	Reason string
}

func (tokenError *AuthTokenAuthenticationFailedError) Error() string {
	if tokenError.Reason == "" {
		return ErrAuthenticationFailed.Error() + ": auth-token rejected"
	}
	return ErrAuthenticationFailed.Error() + ": auth-token rejected: " + tokenError.Reason
}

func (tokenError *AuthTokenAuthenticationFailedError) Unwrap() error {
	return ErrAuthenticationFailed
}

type AuthRetryMode string

const (
	AuthRetryModeNone       AuthRetryMode = "none"
	AuthRetryModeNoInteract AuthRetryMode = "nointeract"
	AuthRetryModeInteract   AuthRetryMode = "interact"
)

// Upstream auth_retry_get defaults unknown --auth-retry values to none.
func resolveAuthRetryMode(value string) AuthRetryMode {
	switch value {
	case string(AuthRetryModeNoInteract):
		return AuthRetryModeNoInteract
	case string(AuthRetryModeInteract):
		return AuthRetryModeInteract
	default:
		return AuthRetryModeNone
	}
}

type AuthFailedTerminalError struct {
	Reason string
}

func (terminalError *AuthFailedTerminalError) Error() string {
	if terminalError.Reason == "" {
		return ErrAuthenticationFailed.Error() + ": terminal (auth-retry none)"
	}
	return ErrAuthenticationFailed.Error() + ": terminal (auth-retry none): " + terminalError.Reason
}

func (terminalError *AuthFailedTerminalError) Unwrap() error {
	return ErrAuthenticationFailed
}

func (terminalError *AuthFailedTerminalError) Terminal() bool {
	return true
}

func parseAuthPendingTimeout(payload []byte) (uint32, bool) {
	normalized := normalizeControlPayload(payload)
	if normalized == "" {
		return 0, false
	}
	if !strings.HasPrefix(strings.ToUpper(normalized), authPendingPayload) {
		return 0, false
	}
	suffix := strings.TrimPrefix(normalized, authPendingPayload)
	if !strings.HasPrefix(suffix, ",") {
		return 0, false
	}
	suffix = strings.TrimPrefix(suffix, ",")
	for fieldEntry := range strings.SplitSeq(suffix, ",") {
		trimmedField := strings.TrimSpace(fieldEntry)
		if !strings.HasPrefix(strings.ToLower(trimmedField), "timeout") {
			continue
		}
		valueText := strings.TrimSpace(strings.TrimPrefix(trimmedField, "timeout"))
		valueText = strings.TrimPrefix(valueText, "=")
		valueText = strings.TrimSpace(valueText)
		parsedTimeout, err := strconv.ParseUint(valueText, 10, 32)
		if err == nil {
			return uint32(parsedTimeout), true
		}
	}
	return 0, false
}

type CRV1Challenge struct {
	StateID       string
	Username      string
	ChallengeText string
	Echo          bool
}

func parseCRV1Challenge(challenge string) (CRV1Challenge, bool) {
	trimmed := strings.TrimSpace(challenge)
	if !strings.HasPrefix(trimmed, "CRV1:") {
		return CRV1Challenge{}, false
	}
	fields := strings.SplitN(strings.TrimPrefix(trimmed, "CRV1:"), ":", 4)
	if len(fields) != 4 {
		return CRV1Challenge{}, false
	}
	flagBag := fields[0]
	stateID := fields[1]
	encodedUsername := fields[2]
	challengeText := fields[3]
	if strings.TrimSpace(stateID) == "" {
		return CRV1Challenge{}, false
	}
	// Upstream get_auth_challenge requires the `R` flag.
	if !strings.ContainsRune(flagBag, 'R') {
		return CRV1Challenge{}, false
	}
	decodedUsername, err := base64.StdEncoding.DecodeString(encodedUsername)
	if err != nil {
		return CRV1Challenge{}, false
	}
	return CRV1Challenge{
		StateID:       stateID,
		Username:      string(decodedUsername),
		ChallengeText: challengeText,
		Echo:          strings.ContainsRune(flagBag, 'E'),
	}, true
}

func extractCRV1FromAuthFailed(payload []byte) (CRV1Challenge, bool) {
	normalized := normalizeControlPayload(payload)
	if normalized == "" {
		return CRV1Challenge{}, false
	}
	if !strings.HasPrefix(strings.ToUpper(normalized), authFailedPayload+",") {
		return CRV1Challenge{}, false
	}
	remainder := strings.TrimPrefix(normalized, authFailedPayload+",")
	crv1Index := strings.Index(remainder, "CRV1:")
	if crv1Index < 0 {
		return CRV1Challenge{}, false
	}
	return parseCRV1Challenge(remainder[crv1Index:])
}

type AuthChallengeError struct {
	Challenge CRV1Challenge
}

func (authError *AuthChallengeError) Error() string {
	return fmt.Sprintf("%s: dynamic challenge required: %s", ErrAuthenticationFailed.Error(), authError.Challenge.ChallengeText)
}

func (authError *AuthChallengeError) Unwrap() error {
	return ErrAuthenticationFailed
}
