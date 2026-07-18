package test

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	. "github.com/sagernet/sing-openvpn"
	"github.com/sagernet/sing-openvpn/proto"
)

func TestTLSUDPPeerIDNATRebindingAndHijackResistance(t *testing.T) {
	serverTransport := newObservedPacketConn(t)
	serverContext, cancelServer := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelServer()
	server, err := NewServer(ServerOptions{
		Context:   serverContext,
		Mode:      ModeTLS,
		Transport: ServerTransportOptions{PacketConn: serverTransport, Protocol: "udp"},
		TLS: ServerTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Authentication: ServerAuthenticationOptions{DuplicateCN: true},
		Tunnel: ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.88.0.0/28")},
			Topology:     "subnet",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}

	firstClient, firstTransport, firstConfiguration := startRebindableTLSClient(t, serverTransport.LocalAddr().String())
	defer firstClient.Close()
	secondClient, secondTransport, secondConfiguration := startRebindableTLSClient(t, serverTransport.LocalAddr().String())
	defer secondClient.Close()
	if firstConfiguration.PeerID == nil || secondConfiguration.PeerID == nil {
		t.Fatalf("server did not negotiate peer-id: first=%v second=%v", firstConfiguration.PeerID, secondConfiguration.PeerID)
	}
	if *firstConfiguration.PeerID == *secondConfiguration.PeerID {
		t.Fatalf("two active clients received the same peer-id: %d", *firstConfiguration.PeerID)
	}

	serverAddress := "10.88.0.1"
	firstAddress := firstConfiguration.LocalIPv4[0].Addr().String()
	secondAddress := secondConfiguration.LocalIPv4[0].Addr().String()
	firstInitialPacket := makeIPv4TestPacket(firstAddress, serverAddress, []byte("first-initial"))
	err = firstClient.WriteDataPacket(firstInitialPacket)
	if err != nil {
		t.Fatal(err)
	}
	firstServerPacket := readServerPacket(t, server, firstInitialPacket)
	firstStablePeer := firstServerPacket.PeerAddress
	secondInitialPacket := makeIPv4TestPacket(secondAddress, serverAddress, []byte("second-initial"))
	err = secondClient.WriteDataPacket(secondInitialPacket)
	if err != nil {
		t.Fatal(err)
	}
	secondServerPacket := readServerPacket(t, server, secondInitialPacket)
	secondStablePeer := secondServerPacket.PeerAddress
	if firstStablePeer == secondStablePeer {
		t.Fatalf("two clients shared one external peer handle: %q", firstStablePeer)
	}

	oldFirstAddress := activeUDPAddress(firstTransport)
	firstTransport.Rebind(t)
	newFirstAddress := activeUDPAddress(firstTransport)
	if oldFirstAddress == newFirstAddress {
		t.Fatalf("client did not change UDP address: %s", oldFirstAddress)
	}
	firstReboundPacket := makeIPv4TestPacket(firstAddress, serverAddress, []byte("first-rebound"))
	err = firstClient.WriteDataPacket(firstReboundPacket)
	if err != nil {
		t.Fatal(err)
	}
	firstServerPacket = readServerPacket(t, server, firstReboundPacket)
	if firstServerPacket.PeerAddress != firstStablePeer {
		t.Fatalf("NAT rebind changed external peer identity: %q -> %q", firstStablePeer, firstServerPacket.PeerAddress)
	}
	firstReply := makeIPv4TestPacket(serverAddress, firstAddress, []byte("reply-on-new-address"))
	err = server.WriteDataPacket(firstStablePeer, firstReply)
	if err != nil {
		t.Fatal(err)
	}
	if reply := readClientPacket(t, firstClient); !bytes.Equal(reply, firstReply) {
		t.Fatalf("reply did not follow authenticated rebind: %x", reply)
	}

	secondStillLive := makeIPv4TestPacket(secondAddress, serverAddress, []byte("second-still-live"))
	err = secondClient.WriteDataPacket(secondStillLive)
	if err != nil {
		t.Fatal(err)
	}
	secondServerPacket = readServerPacket(t, server, secondStillLive)
	if secondServerPacket.PeerAddress != secondStablePeer {
		t.Fatalf("unrelated client identity changed: %q", secondServerPacket.PeerAddress)
	}
	secondReply := makeIPv4TestPacket(serverAddress, secondAddress, []byte("second-reply"))
	err = server.WriteDataPacket(secondStablePeer, secondReply)
	if err != nil {
		t.Fatal(err)
	}
	if reply := readClientPacket(t, secondClient); !bytes.Equal(reply, secondReply) {
		t.Fatalf("second client reply failed after first float: %x", reply)
	}

	routedReply := makeIPv4TestPacket(serverAddress, firstAddress, []byte("route-after-rebind"))
	err = server.WriteDataPacketByDestination(routedReply)
	if err != nil {
		t.Fatal(err)
	}
	if reply := readClientPacket(t, firstClient); !bytes.Equal(reply, routedReply) {
		t.Fatalf("route lookup did not survive rebind: %x", reply)
	}

	validFirstDataV2 := latestDataV2Write(t, firstTransport)
	forged := append([]byte(nil), validFirstDataV2...)
	encodePeerID(forged[1:4], *secondConfiguration.PeerID)
	forged[len(forged)-1] ^= 0x80
	attacker, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	serverUDPAddress, err := net.ResolveUDPAddr("udp4", serverTransport.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	serverTransport.drainObservations()
	_, err = attacker.WriteTo(forged, serverUDPAddress)
	if err != nil {
		t.Fatal(err)
	}
	serverTransport.waitForPacket(t, forged)
	barrier := []byte{0xff, 0x42, 0x41, 0x52, 0x52, 0x49, 0x45, 0x52}
	_, err = attacker.WriteTo(barrier, serverUDPAddress)
	if err != nil {
		t.Fatal(err)
	}
	serverTransport.waitForPacket(t, barrier)
	time.Sleep(100 * time.Millisecond)
	probeReply := makeIPv4TestPacket(serverAddress, secondAddress, []byte("post-forgery-probe"))
	err = server.WriteDataPacket(secondStablePeer, probeReply)
	if err != nil {
		t.Fatal(err)
	}
	if reply := readClientPacket(t, secondClient); !bytes.Equal(reply, probeReply) {
		t.Fatalf("forged peer-id displaced the real client: %x", reply)
	}
	err = attacker.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	attackBuffer := make([]byte, 65535)
	if readCount, _, readErr := attacker.ReadFrom(attackBuffer); readErr == nil {
		t.Fatalf("attacker received %d bytes after invalid data packet", readCount)
	} else if !isTimeoutError(readErr) {
		t.Fatal(readErr)
	}

	switchRebindableUDPConnection(t, firstTransport, 0)
	firstReturnPacket := makeIPv4TestPacket(firstAddress, serverAddress, []byte("first-return-old-address"))
	err = firstClient.WriteDataPacket(firstReturnPacket)
	if err != nil {
		t.Fatal(err)
	}
	firstServerPacket = readServerPacket(t, server, firstReturnPacket)
	if firstServerPacket.PeerAddress != firstStablePeer {
		t.Fatalf("move to former address changed peer handle: %q", firstServerPacket.PeerAddress)
	}
	returnReply := makeIPv4TestPacket(serverAddress, firstAddress, []byte("reply-on-former-address"))
	err = server.WriteDataPacket(firstStablePeer, returnReply)
	if err != nil {
		t.Fatal(err)
	}
	if reply := readClientPacket(t, firstClient); !bytes.Equal(reply, returnReply) {
		t.Fatalf("reply did not follow authenticated return: %x", reply)
	}

	_ = secondTransport
}

func startRebindableTLSClient(t *testing.T, serverAddress string) (*Client, *rebindableUDPConn, TunnelConfiguration) {
	t.Helper()
	transport := newRebindableUDPConn(t, serverAddress)
	clientContext, cancelClient := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancelClient)
	client, err := NewClient(ClientOptions{
		Context: clientContext,
		Mode:    ModeTLS,
		Transport: ClientTransportOptions{
			Remotes: []Remote{clientRemote(t, serverAddress, "udp")},
			DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
				_, _, _ = ctx, network, address
				return transport, nil
			},
			Protocol: "udp",
		},
		TLS: ClientTLSOptions{
			CertificateAuthority: Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Pull: ClientPullOptions{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = client.Start()
	if err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	waitForClientReady(t, client, 5*time.Second)
	configuration := waitForClientIfconfig(t, client, 5*time.Second)
	if len(configuration.LocalIPv4) != 1 {
		_ = client.Close()
		t.Fatalf("missing client IPv4 configuration: %+v", configuration.LocalIPv4)
	}
	return client, transport, configuration
}

func latestDataV2Write(t *testing.T, connection *rebindableUDPConn) []byte {
	t.Helper()
	connection.access.Lock()
	defer connection.access.Unlock()
	for index := len(connection.writes) - 1; index >= 0; index-- {
		packet := connection.writes[index]
		if len(packet) >= 4 && proto.Opcode(packet[0]>>3) == proto.OpcodeDataV2 {
			return append([]byte(nil), packet...)
		}
	}
	t.Fatal("client did not emit P_DATA_V2")
	return nil
}

func encodePeerID(destination []byte, peerID uint32) {
	destination[0] = byte(peerID >> 16)
	destination[1] = byte(peerID >> 8)
	destination[2] = byte(peerID)
}

func activeUDPAddress(connection *rebindableUDPConn) string {
	connection.access.Lock()
	defer connection.access.Unlock()
	return connection.active.LocalAddr().String()
}

func switchRebindableUDPConnection(t *testing.T, connection *rebindableUDPConn, index int) {
	t.Helper()
	connection.access.Lock()
	if index < 0 || index >= len(connection.connections) {
		connection.access.Unlock()
		t.Fatalf("invalid UDP connection index %d", index)
	}
	selected := connection.connections[index]
	connection.active = selected
	readDeadline := connection.readDeadline
	writeDeadline := connection.writeDeadline
	connection.access.Unlock()
	err := selected.SetReadDeadline(readDeadline)
	if err != nil {
		t.Fatal(err)
	}
	err = selected.SetWriteDeadline(writeDeadline)
	if err != nil {
		t.Fatal(err)
	}
}

type observedPacketConn struct {
	net.PacketConn
	observations chan []byte
}

func newObservedPacketConn(t *testing.T) *observedPacketConn {
	t.Helper()
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return &observedPacketConn{
		PacketConn:   packetConn,
		observations: make(chan []byte, 4096),
	}
}

func (c *observedPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	readCount, remoteAddress, err := c.PacketConn.ReadFrom(buffer)
	if err == nil {
		packetCopy := append([]byte(nil), buffer[:readCount]...)
		select {
		case c.observations <- packetCopy:
		default:
		}
	}
	return readCount, remoteAddress, err
}

func (c *observedPacketConn) drainObservations() {
	for {
		select {
		case <-c.observations:
		default:
			return
		}
	}
}

func (c *observedPacketConn) waitForPacket(t *testing.T, expected []byte) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case packet := <-c.observations:
			if bytes.Equal(packet, expected) {
				return
			}
		case <-timer.C:
			t.Fatalf("server did not observe packet %x", expected)
		}
	}
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if networkError, ok := err.(net.Error); ok {
		return networkError.Timeout()
	}
	return false
}
