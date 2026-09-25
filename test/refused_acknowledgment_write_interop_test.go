package test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	"github.com/sagernet/sing-openvpn/proto"
)

const (
	refusedAcknowledgmentHoldPacketID = proto.PacketID(3)
	refusedAcknowledgmentHoldDuration = 400 * time.Millisecond
	refusedAcknowledgmentSettleWindow = 3 * time.Second
)

// reliable_ack_write moves the acknowledgment ids out of the pending list into
// the packet buffer write_control_auth hands to the link, so a dedicated P_ACK
// the link refuses leaves them pending: no reliable send buffer entry holds a
// dedicated acknowledgment, and dropping its ids means the received control
// packets it covered are never acknowledged at all.
type refusedAcknowledgmentPacketConn struct {
	net.PacketConn
	access                sync.Mutex
	heldControlPacket     bool
	refusedAcknowledgment bool
	refusedIDs            []proto.PacketID
	receivedControlIDs    map[proto.PacketID]int
	retransmittedIDs      []proto.PacketID
}

func (c *refusedAcknowledgmentPacketConn) ReadFrom(packet []byte) (int, net.Addr, error) {
	readCount, remoteAddress, err := c.PacketConn.ReadFrom(packet)
	if readCount == 0 || err != nil {
		return readCount, remoteAddress, err
	}
	controlPacket, parseErr := proto.ParsePacket(packet[:readCount])
	if parseErr != nil || !controlPacket.Opcode.IsControl() {
		return readCount, remoteAddress, nil
	}
	c.access.Lock()
	c.receivedControlIDs[controlPacket.ID]++
	if c.receivedControlIDs[controlPacket.ID] > 1 {
		c.retransmittedIDs = append(c.retransmittedIDs, controlPacket.ID)
	}
	holdPacket := controlPacket.Opcode == proto.OpcodeControlV1 &&
		controlPacket.ID == refusedAcknowledgmentHoldPacketID &&
		!c.heldControlPacket
	if holdPacket {
		c.heldControlPacket = true
	}
	c.access.Unlock()
	// The reliable packet before the held one completes no TLS flight, so the
	// TLS object writes nothing while it waits and the only way its arrival
	// reaches the peer is the dedicated acknowledgment of the sender loop.
	if holdPacket {
		time.Sleep(refusedAcknowledgmentHoldDuration)
	}
	return readCount, remoteAddress, nil
}

func (c *refusedAcknowledgmentPacketConn) WriteTo(packet []byte, remoteAddress net.Addr) (int, error) {
	if len(packet) == 0 || proto.Opcode(packet[0]>>3) != proto.OpcodeAcknowledgmentV1 {
		return c.PacketConn.WriteTo(packet, remoteAddress)
	}
	acknowledgment, parseErr := proto.ParsePacket(packet)
	c.access.Lock()
	refuse := !c.refusedAcknowledgment && parseErr == nil && len(acknowledgment.AcknowledgmentIDs) > 0
	if refuse {
		c.refusedAcknowledgment = true
		c.refusedIDs = append(c.refusedIDs, acknowledgment.AcknowledgmentIDs...)
	}
	c.access.Unlock()
	if refuse {
		return 0, syscall.ENOBUFS
	}
	return c.PacketConn.WriteTo(packet, remoteAddress)
}

func (c *refusedAcknowledgmentPacketConn) state() (bool, bool, []proto.PacketID, []proto.PacketID) {
	c.access.Lock()
	defer c.access.Unlock()
	return c.heldControlPacket,
		c.refusedAcknowledgment,
		append([]proto.PacketID{}, c.refusedIDs...),
		append([]proto.PacketID{}, c.retransmittedIDs...)
}

// A dedicated P_ACK_V1 the link refuses never reaches the peer, and the reliable
// send buffer holds no entry which would carry its acknowledgment ids again, so
// dropping them from the pending list leaves the control packets they covered
// unacknowledged for the rest of the session: the peer keeps retransmitting them
// until its hand window expires.
func TestOpenVPNInteropRefusedAcknowledgmentWriteAcknowledgesReceivedControlPackets(t *testing.T) {
	t.Parallel()
	env := requireInteropEnvironmentVersion(t, openVPNInteropDefaultVersion)
	workspace := newInteropWorkspace(t)
	t.Cleanup(func() {
		dumpInteropLogs(t, workspace)
	})

	listenPort := reserveInteropPort(t, "udp")
	packetListener, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", listenPort))
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	refusingListener := &refusedAcknowledgmentPacketConn{
		PacketConn:         packetListener,
		receivedControlIDs: make(map[proto.PacketID]int),
	}

	serverContext, cancelServer := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancelServer()
	server, err := openvpn.NewServer(openvpn.ServerOptions{
		NewOutboundQueue: newTestOutboundQueue,
		Context:          serverContext,
		Mode:             openvpn.ModeTLS,
		Transport: openvpn.ServerTransportOptions{
			PacketConn: refusingListener,
			Protocol:   "udp4",
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
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.37.0.2/24")},
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

	tunnelGateway := netip.MustParseAddr("10.37.0.1")
	dockerLogPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", "refused-ack-client.log"))
	dockerConfigurationPath := filepath.ToSlash(filepath.Join(openVPNInteropRoot, "rendered", "refused-ack-client.conf"))
	clientConfiguration := fmt.Sprintf(`proto udp4
remote host.docker.internal %d
nobind
dev tun
client
remote-cert-tls server
ca %s
cert %s
key %s
max-packet-size 512
cipher AES-256-GCM
data-ciphers AES-256-GCM
auth SHA256
persist-key
persist-tun
verb 4
log %s
`, listenPort,
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "ca.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.crt")),
		filepath.ToSlash(filepath.Join(openVPNInteropRoot, "fixtures", "client.key")),
		dockerLogPath,
	)
	err = os.WriteFile(filepath.Join(workspace.renderedDir, "refused-ack-client.conf"), []byte(clientConfiguration), 0o644)
	if err != nil {
		t.Fatalf("write client config: %v", err)
	}
	clientContainer := startInteropContainer(t, env.docker, dockerContainerOptions{
		Name:  "sing-openvpn-refused-ack-client-" + uniqueDockerName(t.Name()),
		Image: env.image,
		Command: []string{
			"bash",
			"-lc",
			"openvpn --config " + dockerConfigurationPath +
				" --daemon --writepid " + filepath.ToSlash(filepath.Join(openVPNInteropRoot, "client.pid")) +
				" && until grep -q 'Initialization Sequence Completed' " + dockerLogPath + "; do sleep 0.1; done" +
				" && ping -c 3 -W 10 " + tunnelGateway.String(),
		},
		Binds:      []string{workspace.root + ":" + openVPNInteropRoot},
		Privileged: true,
	})

	localClientLogPath := filepath.Join(workspace.logsDir, "refused-ack-client.log")
	waitForLogLine(t, localClientLogPath, "Initialization Sequence Completed", 40*time.Second)

	packetContext, cancelPacket := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancelPacket()
	for {
		packet, readErr := server.ReadDataPacket(packetContext)
		if readErr != nil {
			t.Fatalf("read tunnel packet from real client: %v", readErr)
		}
		reply, replyErr := buildStaticICMPEchoReply(packet.Payload)
		if replyErr != nil {
			continue
		}
		writeErr := server.WriteDataPacket(packet.PeerAddress, reply)
		if writeErr != nil {
			t.Fatalf("write tunnel packet to real client: %v", writeErr)
		}
		break
	}
	waitResult := clientContainer.Wait(t, 40*time.Second)
	if waitResult.ExitCode != 0 {
		t.Fatalf("real OpenVPN client failed: %s", waitResult.Logs)
	}

	// The real peer fast-retransmits a reliable packet once three higher ones
	// are acknowledged and otherwise waits out its --tls-timeout, so a control
	// packet left unacknowledged during the handshake arrives again well inside
	// this window.
	time.Sleep(refusedAcknowledgmentSettleWindow)

	heldControlPacket, refusedAcknowledgment, refusedIDs, retransmittedIDs := refusingListener.state()
	if !heldControlPacket {
		t.Fatalf("no reliable control packet %d was held back, the dedicated acknowledgment is not exercised", refusedAcknowledgmentHoldPacketID)
	}
	if !refusedAcknowledgment {
		t.Fatal("no dedicated P_ACK_V1 write was refused, the dropped acknowledgment ids are not exercised")
	}
	if len(retransmittedIDs) > 0 {
		t.Fatalf("the peer retransmitted reliable control packets %v after the refused acknowledgment of %v", retransmittedIDs, refusedIDs)
	}
}
