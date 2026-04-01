package test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
)

func clientTransportOptions(t *testing.T, address string, protocol string) openvpn.ClientTransportOptions {
	t.Helper()
	return openvpn.ClientTransportOptions{
		Remotes:  []openvpn.Remote{clientRemote(t, address, protocol)},
		Protocol: protocol,
	}
}

func clientRemote(t *testing.T, address string, protocol string) openvpn.Remote {
	t.Helper()
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return openvpn.Remote{
		Host:     host,
		Port:     uint16(port),
		Protocol: protocol,
	}
}

func testHexStaticKey() string {
	staticKeyMaterial := make([]byte, 256)
	for index := range staticKeyMaterial {
		staticKeyMaterial[index] = byte(index)
	}
	return hex.EncodeToString(staticKeyMaterial)
}

func writeTestPEM(t *testing.T, directory string, fileName string, blockType string, derBytes []byte) string {
	t.Helper()
	filePath := filepath.Join(directory, fileName)
	pemBuffer := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: derBytes})
	err := os.WriteFile(filePath, pemBuffer, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	return filePath
}

func writeTestPKCS8Key(t *testing.T, directory string, fileName string, privateKey *ecdsa.PrivateKey) string {
	t.Helper()
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return writeTestPEM(t, directory, fileName, "PRIVATE KEY", pkcs8Bytes)
}

type rebindableUDPConn struct {
	access        sync.Mutex
	remoteAddress *net.UDPAddr
	active        net.PacketConn
	connections   []net.PacketConn
	readDeadline  time.Time
	writeDeadline time.Time
	writes        [][]byte
}

func newRebindableUDPConn(t *testing.T, listenAddress string) *rebindableUDPConn {
	t.Helper()
	remoteAddress, err := net.ResolveUDPAddr("udp4", listenAddress)
	if err != nil {
		t.Fatal(err)
	}
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	connection := &rebindableUDPConn{
		remoteAddress: remoteAddress,
		active:        packetConn,
		connections:   []net.PacketConn{packetConn},
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func readClientPacket(t *testing.T, client *openvpn.Client) []byte {
	t.Helper()
	readContext, cancelRead := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelRead()
	packet, err := client.ReadDataPacket(readContext)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func (c *rebindableUDPConn) Read(buffer []byte) (int, error) {
	c.access.Lock()
	active := c.active
	deadline := c.readDeadline
	c.access.Unlock()
	if !deadline.IsZero() {
		err := active.SetReadDeadline(deadline)
		if err != nil {
			return 0, err
		}
	}
	n, _, err := active.ReadFrom(buffer)
	return n, err
}

func (c *rebindableUDPConn) Write(packet []byte) (int, error) {
	c.access.Lock()
	active := c.active
	remoteAddress := c.remoteAddress
	deadline := c.writeDeadline
	c.writes = append(c.writes, append([]byte{}, packet...))
	c.access.Unlock()
	if !deadline.IsZero() {
		err := active.SetWriteDeadline(deadline)
		if err != nil {
			return 0, err
		}
	}
	return active.WriteTo(packet, remoteAddress)
}

func (c *rebindableUDPConn) Close() error {
	c.access.Lock()
	connections := append([]net.PacketConn(nil), c.connections...)
	c.access.Unlock()
	var closeErr error
	for _, connection := range connections {
		err := connection.Close()
		if closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

func (c *rebindableUDPConn) LocalAddr() net.Addr {
	c.access.Lock()
	defer c.access.Unlock()
	return c.active.LocalAddr()
}

func (c *rebindableUDPConn) RemoteAddr() net.Addr {
	c.access.Lock()
	defer c.access.Unlock()
	return c.remoteAddress
}

func (c *rebindableUDPConn) SetDeadline(deadline time.Time) error {
	c.access.Lock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	active := c.active
	c.access.Unlock()
	err := active.SetReadDeadline(deadline)
	if err != nil {
		return err
	}
	return active.SetWriteDeadline(deadline)
}

func (c *rebindableUDPConn) SetReadDeadline(deadline time.Time) error {
	c.access.Lock()
	c.readDeadline = deadline
	active := c.active
	c.access.Unlock()
	return active.SetReadDeadline(deadline)
}

func (c *rebindableUDPConn) SetWriteDeadline(deadline time.Time) error {
	c.access.Lock()
	c.writeDeadline = deadline
	active := c.active
	c.access.Unlock()
	return active.SetWriteDeadline(deadline)
}

func (c *rebindableUDPConn) Rebind(t *testing.T) {
	t.Helper()
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c.access.Lock()
	c.active = packetConn
	c.connections = append(c.connections, packetConn)
	readDeadline := c.readDeadline
	writeDeadline := c.writeDeadline
	c.access.Unlock()
	err = packetConn.SetReadDeadline(readDeadline)
	if err != nil {
		t.Fatal(err)
	}
	err = packetConn.SetWriteDeadline(writeDeadline)
	if err != nil {
		t.Fatal(err)
	}
}

func reserveListenAddressForProtocol(t *testing.T, protocol string) string {
	t.Helper()
	switch protocol {
	case "tcp", "tcp4":
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		_ = listener.Close()
		return address
	case "tcp6":
		listener, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		_ = listener.Close()
		return address
	case "udp6":
		listener, err := net.ListenPacket("udp6", "[::1]:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.LocalAddr().String()
		_ = listener.Close()
		return address
	default:
		listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.LocalAddr().String()
		_ = listener.Close()
		return address
	}
}

func readServerPacket(t *testing.T, server *openvpn.Server, expectedPayload []byte) openvpn.ServerDataPacket {
	t.Helper()
	serverPacket := readNextServerPacket(t, server)
	if !bytes.Equal(serverPacket.Payload, expectedPayload) {
		t.Fatalf("unexpected server payload: %q", serverPacket.Payload)
	}
	return serverPacket
}

func readNextServerPacket(t *testing.T, server *openvpn.Server) openvpn.ServerDataPacket {
	t.Helper()
	readContext, cancelRead := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelRead()
	serverPacket, err := server.ReadDataPacket(readContext)
	if err != nil {
		t.Fatal(err)
	}
	return serverPacket
}
