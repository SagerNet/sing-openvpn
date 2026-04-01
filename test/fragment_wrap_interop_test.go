package test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	"github.com/sagernet/sing-openvpn/proto"
)

func TestOpenVPNInteropFragmentSequenceWrapDoesNotMixPackets(t *testing.T) {
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})
	serverPort := reserveUDPPort(t)
	serverConfiguration := fmt.Sprintf(`port %d
proto udp4
dev tun
topology subnet
server 10.46.0.0 255.255.255.0
ca %s
cert %s
key %s
dh none
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
fragment 600
persist-key
persist-tun
verb 4
log %s
`, serverPort,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "server.key")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "fragment-server.log")),
	)
	serverConfigurationPath := filepath.Join(workspace.renderedDir, "fragment-server.conf")
	err := os.WriteFile(serverConfigurationPath, []byte(serverConfiguration), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:         "sing-openvpn-fragment-server-" + sanitizeDockerName(t.Name()),
		Image:        env.image,
		Command:      []string{"openvpn", "--config", filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "fragment-server.conf"))},
		Binds:        []string{workspace.root + ":" + openVPNInteropRoot},
		PortBindings: udpPortBinding(serverPort),
		Privileged:   true,
	})
	serverLogPath := filepath.Join(workspace.logsDir, "fragment-server.log")
	waitForLogLine(t, serverLogPath, "Initialization Sequence Completed", 20*time.Second)

	proxy := newFragmentUDPProxy(t, serverPort)
	defer proxy.Close()
	clientContext, cancelClient := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelClient()
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context:   clientContext,
		Mode:      openvpn.ModeTLS,
		Transport: clientTransportOptions(t, proxy.Address(), "udp4"),
		DataChannel: openvpn.ClientDataChannelOptions{
			Fragment: 600,
			Cipher:   "AES-256-GCM",
			Ciphers:  []string{"AES-256-GCM"},
			Auth:     "SHA256",
		},
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Pull: openvpn.ClientPullOptions{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	configuration := waitForClientIfconfig(t, client, 10*time.Second)
	sourceAddress := configuration.LocalIPv4[0].Addr()
	destinationAddress := netip.MustParseAddr("10.46.0.1")

	firstRequest := buildStaticICMPEchoRequest(t, sourceAddress, destinationAddress, 0x4610, 1, bytes.Repeat([]byte{'A'}, 760))
	firstDropDone := proxy.DropServerDataPacket(2, 2)
	writeClientDataPacket(t, client, firstRequest, 5*time.Second)
	waitForFragmentDrop(t, firstDropDone)

	for i := 0; i < 255; i++ {
		request := buildStaticICMPEchoRequest(t,
			sourceAddress,
			destinationAddress,
			0x4610,
			uint16(i+2),
			bytes.Repeat([]byte{byte(i)}, 760),
		)
		writeClientDataPacket(t, client, request, 5*time.Second)
		replyContext, cancelReply := context.WithTimeout(context.Background(), 2*time.Second)
		reply, readErr := client.ReadDataPacket(replyContext)
		cancelReply()
		if readErr != nil {
			t.Fatalf("read intervening fragmented reply %d: %v", i, readErr)
		}
		assertStaticICMPEchoReply(t, request, reply)
	}

	wrappedRequest := buildStaticICMPEchoRequest(t, sourceAddress, destinationAddress, 0x4610, 257, bytes.Repeat([]byte{'D'}, 760))
	wrappedDropDone := proxy.DropServerDataPacket(1, 2)
	writeClientDataPacket(t, client, wrappedRequest, 5*time.Second)
	waitForFragmentDrop(t, wrappedDropDone)
	readContext, cancelRead := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancelRead()
	unexpectedPacket, readErr := client.ReadDataPacket(readContext)
	if readErr == nil {
		t.Fatalf("sequence wrap completed a packet despite a missing wrapped fragment: %x", unexpectedPacket)
	}
	if readContext.Err() == nil {
		t.Fatalf("unexpected wrapped fragment read error: %v", readErr)
	}
}

type fragmentUDPProxy struct {
	t             *testing.T
	connection    *net.UDPConn
	serverAddress *net.UDPAddr
	access        sync.Mutex
	clientAddress *net.UDPAddr
	dropPlan      *fragmentDropPlan
}

type fragmentDropPlan struct {
	dropIndex int
	total     int
	seen      int
	done      chan struct{}
}

func newFragmentUDPProxy(t *testing.T, serverPort int) *fragmentUDPProxy {
	t.Helper()
	listenAddress := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	connection, err := net.ListenUDP("udp4", listenAddress)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &fragmentUDPProxy{
		t:             t,
		connection:    connection,
		serverAddress: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: serverPort},
	}
	go proxy.run()
	return proxy
}

func (p *fragmentUDPProxy) Address() string {
	return p.connection.LocalAddr().String()
}

func (p *fragmentUDPProxy) DropServerDataPacket(dropIndex int, total int) <-chan struct{} {
	p.t.Helper()
	p.access.Lock()
	defer p.access.Unlock()
	if p.dropPlan != nil {
		p.t.Fatal("fragment drop plan already active")
	}
	done := make(chan struct{})
	p.dropPlan = &fragmentDropPlan{dropIndex: dropIndex, total: total, done: done}
	return done
}

func (p *fragmentUDPProxy) Close() error {
	return p.connection.Close()
}

func (p *fragmentUDPProxy) run() {
	packetBuffer := make([]byte, 64<<10)
	for {
		n, sourceAddress, err := p.connection.ReadFromUDP(packetBuffer)
		if err != nil {
			return
		}
		packet := append([]byte{}, packetBuffer[:n]...)
		if sourceAddress.Port == p.serverAddress.Port {
			p.forwardServerPacket(packet)
			continue
		}
		p.access.Lock()
		p.clientAddress = sourceAddress
		p.access.Unlock()
		_, _ = p.connection.WriteToUDP(packet, p.serverAddress)
	}
}

func (p *fragmentUDPProxy) forwardServerPacket(packet []byte) {
	dropPacket := false
	p.access.Lock()
	if len(packet) > 0 && proto.Opcode(packet[0]>>3).IsData() && p.dropPlan != nil {
		p.dropPlan.seen++
		dropPacket = p.dropPlan.seen == p.dropPlan.dropIndex
		if p.dropPlan.seen == p.dropPlan.total {
			close(p.dropPlan.done)
			p.dropPlan = nil
		}
	}
	clientAddress := p.clientAddress
	p.access.Unlock()
	if dropPacket || clientAddress == nil {
		return
	}
	_, _ = p.connection.WriteToUDP(packet, clientAddress)
}

func waitForFragmentDrop(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
		time.Sleep(20 * time.Millisecond)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for fragmented reply")
	}
}
