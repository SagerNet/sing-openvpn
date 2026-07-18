package test

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
)

func TestOpenVPNInteropLongRunningServerStaleSessionNewClientAfterAuth(t *testing.T) {
	for _, version := range []string{"2.4.12", "2.5.11", "2.6.14"} {
		t.Run("openvpn_"+version, func(t *testing.T) {
			runOpenVPNInteropLongRunningServerStaleSessionNewClientAfterAuth(t, requireInteropEnvironmentVersion(t, version))
		})
	}
}

func runOpenVPNInteropLongRunningServerStaleSessionNewClientAfterAuth(t *testing.T, env interopEnvironment) {
	t.Helper()
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	listenPort := reserveUDPPort(t)
	serverContext, cancelServerContext := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancelServerContext()
	var authenticationCount atomic.Uint32
	server, err := openvpn.NewServer(openvpn.ServerOptions{
		Context: serverContext,
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ServerTransportOptions{
			ListenAddress: fmt.Sprintf("0.0.0.0:%d", listenPort),
			Protocol:      "udp4",
		},
		Resources: openvpn.ServerResourceOptions{MaxClients: 1},
		DataChannel: openvpn.ServerDataChannelOptions{
			Ciphers: []string{"AES-256-GCM", "AES-128-GCM"},
		},
		TLS: openvpn.ServerTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Authentication: openvpn.ServerAuthenticationOptions{Authenticator: func(_ context.Context, username string, password string) error {
			if username != "test-user" || password != "test-password" {
				return openvpn.ErrAuthenticationFailed
			}
			authenticationCount.Add(1)
			return nil
		}},
		Timing: openvpn.ServerTimingOptions{
			PingInterval: time.Second,
			PingRestart:  5 * time.Second,
		},
		Tunnel: openvpn.ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
			Topology:     "subnet",
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

	dataCiphersDirective := "data-ciphers"
	if interopVersionRank(env.version) == 24 {
		dataCiphersDirective = "ncp-ciphers"
	}
	firstLogPath := filepath.Join(workspace.logsDir, "stale-first-client.log")
	firstConfigurationPath := filepath.Join(workspace.renderedDir, "stale-first-client.conf")
	renderStaleSessionInteropClient(t, firstConfigurationPath, firstLogPath, listenPort, dataCiphersDirective)
	firstClient := startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:       "sing-openvpn-stale-first-client-" + sanitizeDockerName(t.Name()),
		Image:      env.image,
		Command:    []string{"bash", "-lc", "exec openvpn --config " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "stale-first-client.conf")) + " --connect-timeout 5 --connect-retry-max 1 --hand-window 5"},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})
	waitForAuthenticationCount(t, &authenticationCount, 1, 20*time.Second)
	waitForLogLine(t, firstLogPath, "Initialization Sequence Completed", 20*time.Second)

	removeContext, cancelRemove := context.WithTimeout(context.Background(), 10*time.Second)
	err = removeInteropContainer(removeContext, env.docker, firstClient.containerID)
	cancelRemove()
	if err != nil {
		t.Fatalf("force-remove first OpenVPN client: %v", err)
	}
	time.Sleep(8 * time.Second)

	secondLogPath := filepath.Join(workspace.logsDir, "new-second-client.log")
	secondConfigurationPath := filepath.Join(workspace.renderedDir, "new-second-client.conf")
	renderStaleSessionInteropClient(t, secondConfigurationPath, secondLogPath, listenPort, dataCiphersDirective)
	secondContainerConfiguration := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "new-second-client.conf"))
	secondClientLog := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "new-second-client.log"))
	secondClientPID := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "new-second-client.pid"))
	secondClient := startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:       "sing-openvpn-stale-second-client-" + sanitizeDockerName(t.Name()),
		Image:      env.image,
		Command:    []string{"bash", "-lc", "openvpn --config " + secondContainerConfiguration + " --daemon --writepid " + secondClientPID + " && until grep -q 'Initialization Sequence Completed' " + secondClientLog + "; do sleep 0.1; done && ping -c 1 -W 3 10.8.0.1"},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})
	waitForAuthenticationCount(t, &authenticationCount, 2, 20*time.Second)
	waitForLogLine(t, secondLogPath, "Initialization Sequence Completed", 20*time.Second)

	packetContext, cancelPacket := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelPacket()
	for {
		packet, readErr := server.ReadDataPacket(packetContext)
		if readErr != nil {
			t.Fatalf("read echo request from second OpenVPN client: %v", readErr)
		}
		reply, replyErr := buildStaticICMPEchoReply(packet.Payload)
		if replyErr != nil {
			continue
		}
		writeErr := server.WriteDataPacket(packet.PeerAddress, reply)
		if writeErr != nil {
			t.Fatalf("write echo reply to second OpenVPN client: %v", writeErr)
		}
		break
	}
	waitResult := secondClient.Wait(t, 15*time.Second)
	if waitResult.ExitCode != 0 {
		t.Fatalf("second OpenVPN client failed: %s", waitResult.Logs)
	}
	if authenticationCount.Load() != 2 {
		t.Fatalf("unexpected successful authentication count: %d", authenticationCount.Load())
	}
}

func renderStaleSessionInteropClient(t *testing.T, configurationPath string, logPath string, listenPort int, dataCiphersDirective string) {
	t.Helper()
	renderInteropTemplate(t, "tls-client.conf.tmpl", configurationPath, tlsClientTemplateData{
		Protocol:             "udp4",
		RemoteHost:           "host.docker.internal",
		RemotePort:           listenPort,
		CAPath:               filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		CertPath:             filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.crt")),
		KeyPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.key")),
		DataCiphersDirective: dataCiphersDirective,
		DataCiphers:          strings.Join([]string{"AES-256-GCM", "AES-128-GCM"}, ":"),
		AuthFilePath:         filepath.ToSlash(filepath.Join(openVPNInteropRoot, "scripts", "auth-user-pass.txt")),
		LogPath:              filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", filepath.Base(logPath))),
	})
}

func waitForAuthenticationCount(t *testing.T, count *atomic.Uint32, expected uint32, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if count.Load() >= expected {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d successful authentications; got %d", expected, count.Load())
}
