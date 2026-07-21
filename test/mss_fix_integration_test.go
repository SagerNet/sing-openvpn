package test

import (
	"context"
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
)

func TestMSSFixClientServerDataPathIntegration(t *testing.T) {
	testCases := []struct {
		name           string
		protocol       string
		cipher         string
		mssFix         uint32
		mssFixMode     string
		innerIPv6      bool
		serverToClient bool
		boundaryCases  bool
		expectedMSS    uint16
	}{
		{name: "default_udp4_aead_ipv4_server", protocol: "udp4", cipher: "AES-256-GCM", serverToClient: true, boundaryCases: true, expectedMSS: 1400},
		{name: "default_udp6_cbc_ipv6_server", protocol: "udp6", cipher: "AES-256-CBC", innerIPv6: true, serverToClient: true, boundaryCases: true, expectedMSS: 1327},
		{name: "default_tcp4_cbc_ipv6_client", protocol: "tcp4", cipher: "AES-256-CBC", innerIPv6: true, expectedMSS: 1327},
		{name: "default_tcp6_aead_ipv4_server", protocol: "tcp6", cipher: "AES-256-GCM", serverToClient: true, expectedMSS: 1366},
		{name: "normal_udp4_aead_ipv6_server", protocol: "udp4", cipher: "AES-256-GCM", mssFix: 1200, innerIPv6: true, serverToClient: true, expectedMSS: 1116},
		{name: "normal_tcp6_cbc_ipv4_client", protocol: "tcp6", cipher: "AES-256-CBC", mssFix: 1200, expectedMSS: 1091},
		{name: "fixed_udp6_cbc_ipv4_client", protocol: "udp6", cipher: "AES-256-CBC", mssFix: 1200, mssFixMode: openvpn.MSSFixModeFixed, expectedMSS: 1160},
		{name: "fixed_tcp4_aead_ipv6_server", protocol: "tcp4", cipher: "AES-256-GCM", mssFix: 1200, mssFixMode: openvpn.MSSFixModeFixed, innerIPv6: true, serverToClient: true, expectedMSS: 1140},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			runMSSFixDataPathSession(t, testCase.protocol, testCase.cipher, testCase.mssFix, testCase.mssFixMode, testCase.innerIPv6, testCase.serverToClient, testCase.boundaryCases, testCase.expectedMSS)
		})
	}
}

func runMSSFixDataPathSession(t *testing.T, protocol string, cipher string, mssFix uint32, mssFixMode string, innerIPv6 bool, serverToClient bool, boundaryCases bool, expectedMSS uint16) {
	t.Helper()
	listenAddress := reserveListenAddressForProtocol(t, protocol)
	serverDataChannel := openvpn.ServerDataChannelOptions{
		Ciphers: []string{cipher},
		Auth:    "SHA256",
	}
	clientDataChannel := openvpn.ClientDataChannelOptions{
		Ciphers: []string{cipher},
		Auth:    "SHA256",
	}
	if serverToClient {
		serverDataChannel.MSSFix = mssFix
		serverDataChannel.MSSFixMode = mssFixMode
		clientDataChannel.MSSFixDisabled = true
	} else {
		clientDataChannel.MSSFix = mssFix
		clientDataChannel.MSSFixMode = mssFixMode
		serverDataChannel.MSSFixDisabled = true
	}
	server, err := openvpn.NewServer(openvpn.ServerOptions{
		Context: context.Background(),
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ServerTransportOptions{
			ListenAddress: listenAddress,
			Protocol:      protocol,
		},
		DataChannel: serverDataChannel,
		TLS: openvpn.ServerTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Tunnel: openvpn.ServerTunnelOptions{
			AddressPools: []netip.Prefix{
				netip.MustParsePrefix("10.93.0.0/24"),
				netip.MustParsePrefix("fd93::/64"),
			},
			Topology: "subnet",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}
	clientContext, cancelClient := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancelClient)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context:     clientContext,
		Mode:        openvpn.ModeTLS,
		Transport:   clientTransportOptions(t, listenAddress, protocol),
		DataChannel: clientDataChannel,
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
	t.Cleanup(func() { _ = client.Close() })
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	waitForClientReady(t, client, 5*time.Second)
	configuration := waitForClientIfconfig(t, client, 5*time.Second)
	if len(configuration.LocalIPv6) == 0 {
		t.Fatal("missing assigned IPv6 address")
	}
	var sourceAddress netip.Addr
	var destinationAddress netip.Addr
	if innerIPv6 {
		if serverToClient {
			sourceAddress = netip.MustParseAddr("fd93::1")
			destinationAddress = configuration.LocalIPv6[0].Addr()
		} else {
			sourceAddress = configuration.LocalIPv6[0].Addr()
			destinationAddress = netip.MustParseAddr("fd93::1")
		}
	} else if serverToClient {
		sourceAddress = netip.MustParseAddr("10.93.0.1")
		destinationAddress = configuration.LocalIPv4[0].Addr()
	} else {
		sourceAddress = configuration.LocalIPv4[0].Addr()
		destinationAddress = netip.MustParseAddr("10.93.0.1")
	}
	packet := buildTCPSYNPacket(t, sourceAddress, destinationAddress, 65000)
	receivedPacket := exchangeMSSFixPacket(t, server, client, packet, serverToClient)
	assertTCPSYNMSS(t, receivedPacket, expectedMSS)
	if !boundaryCases {
		return
	}
	if innerIPv6 {
		incompletePacket := append(append([]byte{}, packet...), 0)
		receivedPacket = exchangeMSSFixPacket(t, server, client, incompletePacket, serverToClient)
		assertTCPSYNMSS(t, receivedPacket, 65000)
		return
	}
	fragmentedPacket := append([]byte{}, packet...)
	binary.BigEndian.PutUint16(fragmentedPacket[6:8], 1)
	fragmentedPacket[10] = 0
	fragmentedPacket[11] = 0
	binary.BigEndian.PutUint16(fragmentedPacket[10:12], internetChecksum(fragmentedPacket[:20]))
	receivedPacket = exchangeMSSFixPacket(t, server, client, fragmentedPacket, serverToClient)
	assertTCPSYNMSS(t, receivedPacket, 65000)
	firstFragmentPacket := append([]byte{}, packet...)
	binary.BigEndian.PutUint16(firstFragmentPacket[6:8], 0x2000)
	firstFragmentPacket[10] = 0
	firstFragmentPacket[11] = 0
	binary.BigEndian.PutUint16(firstFragmentPacket[10:12], internetChecksum(firstFragmentPacket[:20]))
	receivedPacket = exchangeMSSFixPacket(t, server, client, firstFragmentPacket, serverToClient)
	assertTCPSYNMSS(t, receivedPacket, 65000)
	incompletePacket := append(append([]byte{}, packet...), 0)
	receivedPacket = exchangeMSSFixPacket(t, server, client, incompletePacket, serverToClient)
	assertTCPSYNMSS(t, receivedPacket, 65000)
}

func exchangeMSSFixPacket(t *testing.T, server *openvpn.Server, client *openvpn.Client, packet []byte, serverToClient bool) []byte {
	t.Helper()
	if serverToClient {
		err := server.WriteDataPacketByDestination(packet)
		if err != nil {
			t.Fatal(err)
		}
		readContext, cancelRead := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelRead()
		receivedPacket, err := client.ReadDataPacket(readContext)
		if err != nil {
			t.Fatal(err)
		}
		return receivedPacket
	}
	err := client.WriteDataPacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	readContext, cancelRead := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelRead()
	serverPacket, err := server.ReadDataPacket(readContext)
	if err != nil {
		t.Fatal(err)
	}
	return serverPacket.Payload
}

func buildTCPSYNPacket(t *testing.T, source netip.Addr, destination netip.Addr, segmentSize uint16) []byte {
	t.Helper()
	if source.Is4() && destination.Is4() {
		return buildIPv4TCPSYNPacket(t, source, destination, 40000, 443, segmentSize)
	}
	if !source.Is6() || !destination.Is6() {
		t.Fatal("TCP SYN address families do not match")
	}
	const (
		ipv6HeaderLength = 40
		tcpHeaderLength  = 24
	)
	packet := make([]byte, ipv6HeaderLength+tcpHeaderLength)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], tcpHeaderLength)
	packet[6] = 6
	packet[7] = 64
	sourceBytes := source.As16()
	destinationBytes := destination.As16()
	copy(packet[8:24], sourceBytes[:])
	copy(packet[24:40], destinationBytes[:])
	tcpSegment := packet[ipv6HeaderLength:]
	binary.BigEndian.PutUint16(tcpSegment[0:2], 40000)
	binary.BigEndian.PutUint16(tcpSegment[2:4], 443)
	binary.BigEndian.PutUint32(tcpSegment[4:8], 1)
	tcpSegment[12] = 6 << 4
	tcpSegment[13] = 0x02
	binary.BigEndian.PutUint16(tcpSegment[14:16], 65535)
	tcpSegment[20] = 2
	tcpSegment[21] = 4
	binary.BigEndian.PutUint16(tcpSegment[22:24], segmentSize)
	pseudoHeader := make([]byte, 40+len(tcpSegment))
	copy(pseudoHeader[0:16], sourceBytes[:])
	copy(pseudoHeader[16:32], destinationBytes[:])
	binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(len(tcpSegment)))
	pseudoHeader[39] = 6
	copy(pseudoHeader[40:], tcpSegment)
	binary.BigEndian.PutUint16(tcpSegment[16:18], internetChecksum(pseudoHeader))
	return packet
}

func assertTCPSYNMSS(t *testing.T, packet []byte, expectedMSS uint16) {
	t.Helper()
	if len(packet) < 44 {
		t.Fatalf("short TCP SYN packet: %d", len(packet))
	}
	ipHeaderLength := 40
	if packet[0]>>4 == 4 {
		ipHeaderLength = int(packet[0]&0x0f) * 4
	}
	mssOffset := ipHeaderLength + 22
	if len(packet) < mssOffset+2 || packet[ipHeaderLength+20] != 2 || packet[ipHeaderLength+21] != 4 {
		t.Fatal("TCP SYN packet has no MSS option")
	}
	actualMSS := binary.BigEndian.Uint16(packet[mssOffset : mssOffset+2])
	if actualMSS != expectedMSS {
		t.Fatalf("expected MSS %d, got %d", expectedMSS, actualMSS)
	}
}
