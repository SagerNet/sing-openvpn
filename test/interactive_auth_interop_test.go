package test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	E "github.com/sagernet/sing/common/exceptions"
)

type interactiveAuthServer struct {
	workspace  interopWorkspace
	serverPort int
	clientPort int
}

func startInteractiveAuthServer(t *testing.T, env interopEnvironment, customize func(data *tlsServerTemplateData)) interactiveAuthServer {
	t.Helper()
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	serverPort := reserveUDPPort(t)
	clientPort := reserveUDPPort(t)
	data := tlsServerTemplateData{
		Protocol: "udp4",
		Port:     serverPort,
		CAPath:   filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		CertPath: filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		KeyPath:  filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		LogPath:  filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "server.log")),
	}
	customize(&data)
	renderInteropTemplate(t, "tls-server.conf.tmpl", filepath.Join(workspace.renderedDir, "server-tls.conf"), data)
	portBindings := udpPortBinding(serverPort)
	if data.ManagementPort > 0 {
		for port, bindings := range tcpPortBinding(data.ManagementPort) {
			portBindings[port] = bindings
		}
	}
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-interactive-server-" + sanitizeDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "server-tls.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: portBindings,
		Privileged:   true,
	})
	waitForLogLine(t, filepath.Join(workspace.logsDir, "server.log"), "Initialization Sequence Completed", 20*time.Second)
	return interactiveAuthServer{
		workspace:  workspace,
		serverPort: serverPort,
		clientPort: clientPort,
	}
}

func (s interactiveAuthServer) clientOptions(ctx context.Context) openvpn.ClientOptions {
	return openvpn.ClientOptions{
		Context: ctx,
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ClientTransportOptions{
			Remotes:     []openvpn.Remote{{Host: "127.0.0.1", Port: uint16(s.serverPort), Protocol: "udp4"}},
			DialContext: bindPortDialContextWithRecorder(s.clientPort, nil),
			Protocol:    "udp4",
		},
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Authentication: openvpn.ClientAuthenticationOptions{
			Username: "test-user",
			Password: "test-password",
		},
		Pull: openvpn.ClientPullOptions{Enabled: true},
	}
}

func startInteractiveAuthClient(t *testing.T, options openvpn.ClientOptions) *openvpn.Client {
	t.Helper()
	client, err := openvpn.NewClient(options)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
	})
	err = client.Start()
	if err != nil {
		t.Fatalf("start client: %v", err)
	}
	return client
}

func waitForChallengeMatching(t *testing.T, client *openvpn.Client, description string, timeout time.Duration, match func(challenge openvpn.Challenge) bool) openvpn.Challenge {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		updated := client.ChallengeUpdated()
		challenge := client.PendingChallenge()
		if challenge != nil && match(*challenge) {
			return *challenge
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if challenge != nil {
				t.Fatalf("timed out waiting for %s challenge, pending challenge: %+v", description, *challenge)
			}
			t.Fatalf("timed out waiting for %s challenge, no challenge pending", description)
		}
		timer := time.NewTimer(remaining)
		select {
		case <-updated:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func waitForNoChallenge(t *testing.T, client *openvpn.Client, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if client.PendingChallenge() == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	challenge := client.PendingChallenge()
	if challenge != nil {
		t.Fatalf("challenge %q (%s) was not cleared after authentication completed", challenge.Message, challenge.Kind)
	}
}

func TestOpenVPNInteropInteractiveOpenURL(t *testing.T) {
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	server := startInteractiveAuthServer(t, env, func(data *tlsServerTemplateData) {
		data.RequireUserPass = true
		data.AuthScriptPath = filepath.ToSlash(filepath.Join(openVPNInteropRoot, "scripts", "deferred_openurl.sh"))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client := startInteractiveAuthClient(t, server.clientOptions(ctx))

	challenge := waitForChallengeMatching(t, client, string(openvpn.ChallengeOpenURL), 20*time.Second, func(candidate openvpn.Challenge) bool {
		return candidate.Kind == openvpn.ChallengeOpenURL
	})
	if challenge.URL != "https://auth.example.test/session-42" {
		t.Fatalf("unexpected open-url challenge URL: %q", challenge.URL)
	}
	if challenge.Deadline.IsZero() {
		t.Fatal("open-url challenge is missing the pending-auth deadline")
	}
	err := client.CompleteChallenge(challenge.ID, openvpn.ChallengeResponse{Secret: "unexpected"})
	if !E.IsMulti(err, openvpn.ErrChallengeNotAnswerable) {
		t.Fatalf("expected ErrChallengeNotAnswerable for open-url challenge, got: %v", err)
	}
	if client.PendingChallenge() == nil {
		t.Fatal("open-url challenge was dropped by the rejected completion attempt")
	}
	waitForClientIfconfig(t, client, 30*time.Second)
	waitForNoChallenge(t, client, 10*time.Second)
}

func TestOpenVPNInteropInteractiveCRText(t *testing.T) {
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	server := startInteractiveAuthServer(t, env, func(data *tlsServerTemplateData) {
		data.RequireUserPass = true
		data.AuthScriptPath = filepath.ToSlash(filepath.Join(openVPNInteropRoot, "scripts", "deferred_crtext.sh"))
		data.CRResponseScriptPath = filepath.ToSlash(filepath.Join(openVPNInteropRoot, "scripts", "crresponse_check.sh"))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	client := startInteractiveAuthClient(t, server.clientOptions(ctx))

	challenge := waitForChallengeMatching(t, client, string(openvpn.ChallengeSecret), 20*time.Second, func(candidate openvpn.Challenge) bool {
		return candidate.Kind == openvpn.ChallengeSecret
	})
	if challenge.Message != "Enter the code" {
		t.Fatalf("unexpected cr-text challenge message: %q", challenge.Message)
	}
	if !challenge.Echo {
		t.Fatal("cr-text challenge did not carry the E flag")
	}
	if challenge.PreviousError != "" {
		t.Fatalf("first cr-text challenge unexpectedly carries a previous error: %q", challenge.PreviousError)
	}
	err := client.CompleteChallenge(challenge.ID, openvpn.ChallengeResponse{Secret: "000000"})
	if err != nil {
		t.Fatalf("complete cr-text challenge with wrong code: %v", err)
	}
	retryChallenge := waitForChallengeMatching(t, client, "retried cr-text", 60*time.Second, func(candidate openvpn.Challenge) bool {
		return candidate.Kind == openvpn.ChallengeSecret && candidate.ID != challenge.ID && candidate.PreviousError != ""
	})
	if retryChallenge.Message != "Enter the code" {
		t.Fatalf("unexpected retried cr-text challenge message: %q", retryChallenge.Message)
	}
	err = client.CompleteChallenge(retryChallenge.ID, openvpn.ChallengeResponse{Secret: "424242"})
	if err != nil {
		t.Fatalf("complete cr-text challenge: %v", err)
	}
	waitForClientIfconfig(t, client, 30*time.Second)
	waitForNoChallenge(t, client, 10*time.Second)
}

func TestOpenVPNInteropInteractiveCRTextMessage(t *testing.T) {
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	server := startInteractiveAuthServer(t, env, func(data *tlsServerTemplateData) {
		data.RequireUserPass = true
		data.AuthScriptPath = filepath.ToSlash(filepath.Join(openVPNInteropRoot, "scripts", "deferred_crtext_message.sh"))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client := startInteractiveAuthClient(t, server.clientOptions(ctx))

	challenge := waitForChallengeMatching(t, client, string(openvpn.ChallengeMessage), 20*time.Second, func(candidate openvpn.Challenge) bool {
		return candidate.Kind == openvpn.ChallengeMessage
	})
	if challenge.Message != "Verification in progress" {
		t.Fatalf("unexpected cr-text message challenge message: %q", challenge.Message)
	}
	err := client.CompleteChallenge(challenge.ID, openvpn.ChallengeResponse{Secret: "unexpected"})
	if !E.IsMulti(err, openvpn.ErrChallengeNotAnswerable) {
		t.Fatalf("expected ErrChallengeNotAnswerable for message challenge, got: %v", err)
	}
	waitForClientIfconfig(t, client, 30*time.Second)
	waitForNoChallenge(t, client, 10*time.Second)
}

func TestOpenVPNInteropInteractiveCRTextCancel(t *testing.T) {
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	server := startInteractiveAuthServer(t, env, func(data *tlsServerTemplateData) {
		data.RequireUserPass = true
		data.AuthScriptPath = filepath.ToSlash(filepath.Join(openVPNInteropRoot, "scripts", "deferred_crtext.sh"))
		data.CRResponseScriptPath = filepath.ToSlash(filepath.Join(openVPNInteropRoot, "scripts", "crresponse_check.sh"))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client := startInteractiveAuthClient(t, server.clientOptions(ctx))

	challenge := waitForChallengeMatching(t, client, string(openvpn.ChallengeSecret), 20*time.Second, func(candidate openvpn.Challenge) bool {
		return candidate.Kind == openvpn.ChallengeSecret
	})
	err := client.CancelChallenge(challenge.ID)
	if err != nil {
		t.Fatalf("cancel cr-text challenge: %v", err)
	}
	if client.PendingChallenge() != nil {
		t.Fatal("challenge still pending after cancellation")
	}
	waitForClientTerminalError(t, client, 15*time.Second, openvpn.ErrChallengeCanceled)
}

func TestOpenVPNInteropInteractiveStaticChallenge(t *testing.T) {
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	server := startInteractiveAuthServer(t, env, func(data *tlsServerTemplateData) {
		data.RequireUserPass = true
		data.AuthScriptPath = filepath.ToSlash(filepath.Join(openVPNInteropRoot, "scripts", "check_scrv1.sh"))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	clientOptions := server.clientOptions(ctx)
	clientOptions.Authentication.StaticChallenge = "Enter OTP"
	clientOptions.Authentication.StaticChallengeEcho = true
	client := startInteractiveAuthClient(t, clientOptions)

	challenge := waitForChallengeMatching(t, client, string(openvpn.ChallengeSecret), 20*time.Second, func(candidate openvpn.Challenge) bool {
		return candidate.Kind == openvpn.ChallengeSecret
	})
	if challenge.Message != "Enter OTP" {
		t.Fatalf("unexpected static challenge message: %q", challenge.Message)
	}
	if !challenge.Echo {
		t.Fatal("static challenge did not carry the configured echo flag")
	}
	if challenge.PreviousError != "" {
		t.Fatalf("first static challenge unexpectedly carries a previous error: %q", challenge.PreviousError)
	}
	err := client.CompleteChallenge(challenge.ID, openvpn.ChallengeResponse{Secret: "00000"})
	if err != nil {
		t.Fatalf("complete static challenge with wrong OTP: %v", err)
	}
	retryChallenge := waitForChallengeMatching(t, client, "retried static", 60*time.Second, func(candidate openvpn.Challenge) bool {
		return candidate.Kind == openvpn.ChallengeSecret && candidate.ID != challenge.ID && candidate.PreviousError != ""
	})
	if retryChallenge.Message != "Enter OTP" {
		t.Fatalf("unexpected retried static challenge message: %q", retryChallenge.Message)
	}
	err = client.CompleteChallenge(retryChallenge.ID, openvpn.ChallengeResponse{Secret: "31337"})
	if err != nil {
		t.Fatalf("complete static challenge: %v", err)
	}
	waitForClientIfconfig(t, client, 30*time.Second)
	waitForNoChallenge(t, client, 10*time.Second)
}

func TestOpenVPNInteropInteractiveCredentialsWithStaticChallenge(t *testing.T) {
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	server := startInteractiveAuthServer(t, env, func(data *tlsServerTemplateData) {
		data.RequireUserPass = true
		data.AuthScriptPath = filepath.ToSlash(filepath.Join(openVPNInteropRoot, "scripts", "check_scrv1.sh"))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	clientOptions := server.clientOptions(ctx)
	clientOptions.Authentication.Username = ""
	clientOptions.Authentication.Password = ""
	clientOptions.Authentication.StaticChallenge = "Enter OTP"
	clientOptions.Authentication.StaticChallengeEcho = true
	client := startInteractiveAuthClient(t, clientOptions)

	challenge := waitForChallengeMatching(t, client, string(openvpn.ChallengeCredentials), 20*time.Second, func(candidate openvpn.Challenge) bool {
		return candidate.Kind == openvpn.ChallengeCredentials
	})
	if challenge.SecretMessage != "Enter OTP" {
		t.Fatalf("unexpected credentials challenge secret message: %q", challenge.SecretMessage)
	}
	if !challenge.Echo {
		t.Fatal("credentials challenge did not carry the static-challenge echo flag")
	}
	err := client.CompleteChallenge(challenge.ID, openvpn.ChallengeResponse{
		Username: "test-user",
		Password: "test-password",
		Secret:   "31337",
	})
	if err != nil {
		t.Fatalf("complete credentials challenge: %v", err)
	}
	waitForClientIfconfig(t, client, 30*time.Second)
	waitForNoChallenge(t, client, 10*time.Second)
}

func TestOpenVPNInteropInteractiveDynamicCRV1(t *testing.T) {
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	managementPort := reserveTCPPort(t)
	server := startInteractiveAuthServer(t, env, func(data *tlsServerTemplateData) {
		data.ManagementPort = managementPort
	})
	management := dialManagementInterface(t, managementPort)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	client := startInteractiveAuthClient(t, server.clientOptions(ctx))

	firstConnect := management.awaitClientConnect(t, 30*time.Second)
	if firstConnect.env["password"] != "test-password" {
		t.Fatalf("unexpected initial password in management env: %q", firstConnect.env["password"])
	}
	management.send(t, "client-deny "+firstConnect.cid+" "+firstConnect.kid+
		` "denied" "CRV1:R,E:test-state-1:dGVzdC11c2Vy:Please enter token PIN"`)

	challenge := waitForChallengeMatching(t, client, string(openvpn.ChallengeSecret), 30*time.Second, func(candidate openvpn.Challenge) bool {
		return candidate.Kind == openvpn.ChallengeSecret
	})
	if challenge.Message != "Please enter token PIN" {
		t.Fatalf("unexpected CRV1 challenge message: %q", challenge.Message)
	}
	if challenge.Username != "test-user" {
		t.Fatalf("unexpected CRV1 challenge username: %q", challenge.Username)
	}
	if !challenge.Echo {
		t.Fatal("CRV1 challenge did not carry the E flag")
	}
	err := client.CompleteChallenge(challenge.ID, openvpn.ChallengeResponse{Secret: "8675309"})
	if err != nil {
		t.Fatalf("complete CRV1 challenge: %v", err)
	}

	secondConnect := management.awaitClientConnect(t, 30*time.Second)
	if secondConnect.env["username"] != "test-user" {
		t.Fatalf("unexpected CRV1 reconnect username: %q", secondConnect.env["username"])
	}
	if secondConnect.env["password"] != "CRV1::test-state-1::8675309" {
		t.Fatalf("unexpected CRV1 reconnect password: %q", secondConnect.env["password"])
	}
	management.send(t, "client-auth-nt "+secondConnect.cid+" "+secondConnect.kid)

	waitForClientIfconfig(t, client, 30*time.Second)
	waitForNoChallenge(t, client, 10*time.Second)
}

type managementInterface struct {
	conn   net.Conn
	reader *bufio.Reader
}

type managementClientConnect struct {
	cid string
	kid string
	env map[string]string
}

func dialManagementInterface(t *testing.T, port int) *managementInterface {
	t.Helper()
	var conn net.Conn
	var err error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)), time.Second)
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial management interface: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})
	return &managementInterface{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}
}

func (m *managementInterface) send(t *testing.T, command string) {
	t.Helper()
	_, err := m.conn.Write([]byte(command + "\n"))
	if err != nil {
		t.Fatalf("write management command %q: %v", command, err)
	}
}

func (m *managementInterface) awaitClientConnect(t *testing.T, timeout time.Duration) managementClientConnect {
	t.Helper()
	err := m.conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		t.Fatalf("set management read deadline: %v", err)
	}
	connect := managementClientConnect{env: make(map[string]string)}
	inConnectBlock := false
	for {
		line, readErr := m.reader.ReadString('\n')
		if readErr != nil {
			t.Fatalf("read management notification: %v", readErr)
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case strings.HasPrefix(line, ">CLIENT:CONNECT,"):
			fields := strings.Split(strings.TrimPrefix(line, ">CLIENT:CONNECT,"), ",")
			if len(fields) != 2 {
				t.Fatalf("unexpected CLIENT:CONNECT notification: %q", line)
			}
			connect.cid = fields[0]
			connect.kid = fields[1]
			inConnectBlock = true
		case inConnectBlock && line == ">CLIENT:ENV,END":
			return connect
		case inConnectBlock && strings.HasPrefix(line, ">CLIENT:ENV,"):
			name, value, hasValue := strings.Cut(strings.TrimPrefix(line, ">CLIENT:ENV,"), "=")
			if hasValue {
				connect.env[name] = value
			}
		}
	}
}
