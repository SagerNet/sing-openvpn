package test

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// apply_push_options (options.c) cuts a PUSH_REPLY payload into option lines
	// with buf_parse(buf, ',') and processes no escape at all; parse_line
	// (options.c) then splits one line into parameters and is the only place a
	// backslash means anything, so these two backslashes reach the peer verbatim
	// and the peer reads them as one.
	pushedBackslashOptionOnWire   = `DOMAIN pushed\\backslash.example`
	pushedBackslashOptionAsParsed = `DOMAIN pushed\backslash.example`
	// OpenVPN 2.6.14 reports "Bad backslash ('\') usage" and drops the whole
	// option line whenever a backslash precedes anything but '\', '"' or
	// whitespace, so a peer that invents its own escape layer silently loses
	// options rather than delivering them.
	pushedOptionBadBackslashWarning = `Bad backslash ('\') usage`
	pushedBackslashOptionRouteCount = 40
)

// A real OpenVPN server writes every pushed option into the PUSH_REPLY payload
// byte for byte and separates them with a bare comma, and a real OpenVPN client
// undoes exactly one parse_line pass over each option line. Escaping the value
// on the way out, or undoing an escape pass per received PUSH_REPLY segment,
// shifts the peer's view of the option by one backslash level in either
// direction.
func TestOpenVPNInteropPushReplyOptionValuesCarryNoInventedEscaping(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	t.Run("real_client_reads_the_option_this_server_pushed", func(caseTest *testing.T) {
		caseTest.Parallel()
		runPushedBackslashOptionServerCase(caseTest, env)
	})
	t.Run("this_client_reads_the_option_a_real_server_pushed", func(caseTest *testing.T) {
		caseTest.Parallel()
		runPushedBackslashOptionClientCase(caseTest, env)
	})
}

func runPushedBackslashOptionServerCase(t *testing.T, env interopEnvironment) {
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	listenPort := reserveInteropPort(t, "udp")
	serverContext, cancelServer := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancelServer()
	server, err := openvpn.NewServer(openvpn.ServerOptions{
		NewOutboundQueue: newTestOutboundQueue,
		Context:          serverContext,
		Mode:             openvpn.ModeTLS,
		Transport: openvpn.ServerTransportOptions{
			ListenAddress: fmt.Sprintf("0.0.0.0:%d", listenPort),
			Protocol:      "udp4",
		},
		DataChannel: openvpn.ServerDataChannelOptions{
			Ciphers:        []string{"AES-256-GCM"},
			FallbackCipher: "AES-256-GCM",
			Auth:           "SHA256",
		},
		TLS: openvpn.ServerTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Tunnel: openvpn.ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
		},
		Push: openvpn.ServerPushOptions{
			DHCPOptions: []string{pushedBackslashOptionOnWire},
		},
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatalf("start server: %v", err)
	}

	dockerClientLogPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "client.log"))
	renderInteropTemplate(t, "tls-client.conf.tmpl", filepath.Join(workspace.renderedDir, "client-tls.conf"), tlsClientTemplateData{
		Protocol:             "udp4",
		RemoteHost:           "host.docker.internal",
		RemotePort:           listenPort,
		CAPath:               filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		CertPath:             filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.crt")),
		KeyPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.key")),
		Cipher:               "AES-256-GCM",
		Auth:                 "SHA256",
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          "AES-256-GCM",
		UpScriptPath:         filepath.ToSlash(filepath.Join(openVPNInteropRoot, "scripts", "capture_foreign_options.sh")),
		LogPath:              dockerClientLogPath,
	})
	clientContainer := startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:  "sing-openvpn-pushed-backslash-client-" + uniqueDockerName(t.Name()),
		Image: env.image,
		Command: []string{
			"bash",
			"-lc",
			"openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "client-tls.conf")) +
				" --daemon --writepid " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "client.pid")) +
				" && until grep -q 'Initialization Sequence Completed' " + dockerClientLogPath + "; do sleep 0.1; done",
		},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})

	localClientLogPath := filepath.Join(workspace.logsDir, "client.log")
	waitForLogLine(t, localClientLogPath, "Initialization Sequence Completed", 40*time.Second)
	waitResult := clientContainer.Wait(t, 40*time.Second)
	if waitResult.ExitCode != 0 {
		t.Fatalf("real OpenVPN client failed: %s", waitResult.Logs)
	}

	foreignOptions := readInteropForeignOptions(t, filepath.Join(workspace.logsDir, "client-foreign.env"))
	wantForeignOptions := []string{"dhcp-option " + pushedBackslashOptionAsParsed}
	if !slices.Equal(foreignOptions, wantForeignOptions) {
		t.Fatalf("real OpenVPN client imported %q, want %q", foreignOptions, wantForeignOptions)
	}
	clientLogContent, err := os.ReadFile(localClientLogPath)
	if err != nil {
		t.Fatalf("read client log: %v", err)
	}
	if strings.Contains(string(clientLogContent), pushedOptionBadBackslashWarning) {
		t.Fatalf("real OpenVPN client rejected a backslash this server put on the wire\n%s", string(clientLogContent))
	}
}

func runPushedBackslashOptionClientCase(t *testing.T, env interopEnvironment) {
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	// The pushed line passes through parse_line once while the real server reads
	// its own configuration file, so the doubled backslashes below are what
	// reaches the wire.
	pushLines := []string{"dhcp-option " + strings.ReplaceAll(pushedBackslashOptionOnWire, `\`, `\\`)}
	for routeIndex := 1; routeIndex <= pushedBackslashOptionRouteCount; routeIndex++ {
		pushLines = append(pushLines, "route 10."+strconv.Itoa(routeIndex)+".0.0 255.255.255.0")
	}
	serverPort := reserveInteropPort(t, "udp")
	renderInteropTemplate(t, "tls-server.conf.tmpl", filepath.Join(workspace.renderedDir, "pushed-backslash-server.conf"), tlsServerTemplateData{
		Protocol:             "udp4",
		Port:                 serverPort,
		CAPath:               filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		CertPath:             filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		KeyPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		Cipher:               "AES-256-GCM",
		Auth:                 "SHA256",
		DataCiphersDirective: "data-ciphers",
		DataCiphers:          "AES-256-GCM",
		PushLines:            pushLines,
		LogPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "pushed-backslash-server.log")),
	})
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-pushed-backslash-server-" + uniqueDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"bash", "-lc", "openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "pushed-backslash-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	serverLogPath := filepath.Join(workspace.logsDir, "pushed-backslash-server.log")
	waitForLogLine(t, serverLogPath, "Initialization Sequence Completed", 20*time.Second)

	clientContext, cancelClient := context.WithTimeout(context.Background(), 90*time.Second)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context: clientContext,
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ClientTransportOptions{
			Remotes:  []openvpn.Remote{{Host: "127.0.0.1", Port: uint16(serverPort), Protocol: "udp4"}},
			Protocol: "udp4",
		},
		DataChannel: openvpn.ClientDataChannelOptions{
			Cipher:  "AES-256-GCM",
			Ciphers: []string{"AES-256-GCM"},
			Auth:    "SHA256",
		},
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
			RemoteCertificateTLS: "server",
		},
		Pull:   openvpn.ClientPullOptions{Enabled: true},
		Timing: openvpn.ClientTimingOptions{HandWindow: 20 * time.Second},
	})
	if err != nil {
		cancelClient()
		t.Fatalf("create pushed backslash client: %v", err)
	}
	t.Cleanup(func() {
		cancelClient()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosedOrCanceled(closeErr) {
			t.Errorf("close pushed backslash client: %v", closeErr)
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatalf("start pushed backslash client: %v", err)
	}
	configuration := waitForClientIfconfig(t, client, 20*time.Second)

	// Without this the reply arrives in one piece and never exercises the
	// rejoin of the accumulated segments.
	assertLogContains(t, serverLogPath, []string{"push-continuation 2"})
	if !slices.Contains(configuration.DHCPOptions, pushedBackslashOptionAsParsed) {
		t.Fatalf("client imported dhcp-options %q, want one of them to be %q", configuration.DHCPOptions, pushedBackslashOptionAsParsed)
	}
}

func readInteropForeignOptions(t *testing.T, path string) []string {
	t.Helper()
	waitForFile(t, path, 20*time.Second)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read captured foreign options: %v", err)
	}
	foreignOptions := make([]string, 0, 1)
	for line := range strings.SplitSeq(strings.TrimRight(string(content), "\n"), "\n") {
		_, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		foreignOptions = append(foreignOptions, value)
	}
	return foreignOptions
}
