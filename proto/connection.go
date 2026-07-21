package proto

import (
	stdBufio "bufio"
	"encoding/binary"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type PacketConnection interface {
	ReadPacket() ([]byte, error)
	ReadPackets() ([]*buf.Buffer, error)
	WritePacket(packet []byte) error
	WritePackets(packets [][]byte) (int, error)
	WritePacketBuffers(packetBuffers []*buf.Buffer) (int, error)
	SetReadDeadline(deadline time.Time) error
	SetWriteDeadline(deadline time.Time) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

const packetConnectionBatchSize = 64

var ErrPacketTooLarge = E.New("packet too large")

func NewPacketConnection(connection net.Conn, protocol string) (PacketConnection, error) {
	switch {
	case strings.HasPrefix(protocol, "tcp"):
		return &streamPacketConnection{
			connection: connection,
			writer:     bufio.NewVectorisedWriter(connection),
		}, nil
	case strings.HasPrefix(protocol, "udp"):
		packetConnection := &datagramPacketConnection{connection: connection}
		unboundConnection := bufio.NewUnbindPacketConn(connection)
		packetConnection.batchReader, _ = bufio.CreateConnectedPacketBatchReadWaiter(unboundConnection)
		if packetConnection.batchReader != nil {
			packetConnection.batchReader.InitializeReadWaiter(N.ReadWaitOptions{
				MTU:       math.MaxUint16,
				BatchSize: packetConnectionBatchSize,
			})
		}
		packetConnection.batchWriter, _ = bufio.CreateConnectedPacketBatchWriter(unboundConnection)
		return packetConnection, nil
	default:
		return nil, E.New("unsupported protocol")
	}
}

type streamPacketConnection struct {
	connection  net.Conn
	reader      *stdBufio.Reader
	writer      N.VectorisedWriter
	readAccess  sync.Mutex
	writeAccess sync.Mutex
}

func (c *streamPacketConnection) ReadPacket() ([]byte, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	return c.readPacket()
}

func (c *streamPacketConnection) readPacket() ([]byte, error) {
	reader := io.Reader(c.connection)
	if c.reader != nil {
		reader = c.reader
	}
	var lengthBuffer [2]byte
	_, err := io.ReadFull(reader, lengthBuffer[:])
	if err != nil {
		return nil, err
	}
	packetLength := binary.BigEndian.Uint16(lengthBuffer[:])
	packet := make([]byte, packetLength)
	_, err = io.ReadFull(reader, packet)
	if err != nil {
		return nil, err
	}
	return packet, nil
}

func (c *streamPacketConnection) ReadPackets() ([]*buf.Buffer, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	if c.reader == nil {
		c.reader = stdBufio.NewReaderSize(c.connection, buf.UDPBufferSize)
	}
	packetBuffer, err := c.readPacketBuffer()
	if err != nil {
		return nil, err
	}
	packetBuffers := make([]*buf.Buffer, 1, packetConnectionBatchSize)
	packetBuffers[0] = packetBuffer
	for len(packetBuffers) < packetConnectionBatchSize && c.reader.Buffered() >= 2 {
		lengthBuffer, peekErr := c.reader.Peek(2)
		if peekErr != nil {
			break
		}
		packetLength := int(binary.BigEndian.Uint16(lengthBuffer))
		if c.reader.Buffered() < 2+packetLength {
			break
		}
		packetBuffer, err = c.readPacketBuffer()
		if err != nil {
			return packetBuffers, err
		}
		packetBuffers = append(packetBuffers, packetBuffer)
	}
	return packetBuffers, nil
}

func (c *streamPacketConnection) readPacketBuffer() (*buf.Buffer, error) {
	reader := io.Reader(c.connection)
	if c.reader != nil {
		reader = c.reader
	}
	var lengthBuffer [2]byte
	_, err := io.ReadFull(reader, lengthBuffer[:])
	if err != nil {
		return nil, err
	}
	packetLength := int(binary.BigEndian.Uint16(lengthBuffer[:]))
	packetBuffer := buf.NewSize(packetLength)
	_, err = io.ReadFull(reader, packetBuffer.Extend(packetLength))
	if err != nil {
		packetBuffer.Release()
		return nil, err
	}
	return packetBuffer, nil
}

func (c *streamPacketConnection) WritePacket(packet []byte) error {
	_, err := c.WritePackets([][]byte{packet})
	return err
}

func (c *streamPacketConnection) WritePackets(packets [][]byte) (int, error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	packetCount := len(packets)
	var validationErr error
	for i, packet := range packets {
		if len(packet) > math.MaxUint16 {
			packetCount = i
			validationErr = ErrPacketTooLarge
			break
		}
	}
	if packetCount == 0 {
		return 0, validationErr
	}
	totalLength := 0
	for _, packet := range packets[:packetCount] {
		totalLength += 2 + len(packet)
	}
	packetBatch := make([]byte, totalLength)
	offset := 0
	for _, packet := range packets[:packetCount] {
		binary.BigEndian.PutUint16(packetBatch[offset:offset+2], uint16(len(packet)))
		offset += 2
		copy(packetBatch[offset:], packet)
		offset += len(packet)
	}
	writtenBytes := 0
	var writeErr error
	for writtenBytes < len(packetBatch) {
		var n int
		n, writeErr = c.connection.Write(packetBatch[writtenBytes:])
		writtenBytes += n
		if writeErr != nil {
			break
		}
		if n == 0 {
			writeErr = io.ErrShortWrite
			break
		}
	}
	writtenPackets := 0
	writtenLength := 0
	for _, packet := range packets[:packetCount] {
		writtenLength += 2 + len(packet)
		if writtenLength > writtenBytes {
			break
		}
		writtenPackets++
	}
	if writeErr != nil {
		if writtenBytes < len(packetBatch) && (writtenBytes > 0 || writeErr == io.ErrShortWrite) {
			writeErr = E.Errors(writeErr, c.connection.Close())
		}
		return writtenPackets, writeErr
	}
	return writtenPackets, validationErr
}

func (c *streamPacketConnection) WritePacketBuffers(packetBuffers []*buf.Buffer) (int, error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	packetCount := len(packetBuffers)
	var validationErr error
	for i, packetBuffer := range packetBuffers {
		if packetBuffer.Len() > math.MaxUint16 {
			packetCount = i
			validationErr = ErrPacketTooLarge
			break
		}
	}
	if packetCount == 0 {
		buf.ReleaseMulti(packetBuffers)
		return 0, validationErr
	}
	writeBuffers := packetBuffers[:packetCount]
	for i, packetBuffer := range writeBuffers {
		if packetBuffer.Start() < 2 {
			newPacketBuffer := buf.NewSize(2 + packetBuffer.Len())
			newPacketBuffer.Resize(2, 0)
			_, _ = newPacketBuffer.Write(packetBuffer.Bytes())
			packetBuffer.Release()
			packetBuffer = newPacketBuffer
			writeBuffers[i] = newPacketBuffer
		}
		packetLength := packetBuffer.Len()
		binary.BigEndian.PutUint16(packetBuffer.ExtendHeader(2), uint16(packetLength))
	}
	buf.ReleaseMulti(packetBuffers[packetCount:])
	err := c.writer.WriteVectorised(writeBuffers)
	if err != nil {
		return 0, err
	}
	return packetCount, validationErr
}

func (c *streamPacketConnection) SetReadDeadline(deadline time.Time) error {
	return c.connection.SetReadDeadline(deadline)
}

func (c *streamPacketConnection) SetWriteDeadline(deadline time.Time) error {
	return c.connection.SetWriteDeadline(deadline)
}

func (c *streamPacketConnection) Close() error {
	return c.connection.Close()
}

func (c *streamPacketConnection) LocalAddr() net.Addr {
	return c.connection.LocalAddr()
}

func (c *streamPacketConnection) RemoteAddr() net.Addr {
	return c.connection.RemoteAddr()
}

type datagramPacketConnection struct {
	connection  net.Conn
	readAccess  sync.Mutex
	batchReader N.ConnectedPacketBatchReadWaiter
	batchWriter N.ConnectedPacketBatchWriter
}

func (c *datagramPacketConnection) ReadPacket() ([]byte, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	return c.readPacket()
}

func (c *datagramPacketConnection) readPacket() ([]byte, error) {
	packetBuffer := make([]byte, math.MaxUint16)
	packetLength, err := c.connection.Read(packetBuffer)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, packetLength)
	copy(packet, packetBuffer[:packetLength])
	return packet, nil
}

func (c *datagramPacketConnection) ReadPackets() ([]*buf.Buffer, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	if c.batchReader != nil {
		packetBuffers, _, err := c.batchReader.WaitReadConnectedPackets()
		return packetBuffers, err
	}
	packet, err := c.readPacket()
	if err != nil {
		return nil, err
	}
	return []*buf.Buffer{buf.As(packet)}, nil
}

func (c *datagramPacketConnection) WritePacket(packet []byte) error {
	_, err := c.WritePackets([][]byte{packet})
	return err
}

func (c *datagramPacketConnection) WritePackets(packets [][]byte) (int, error) {
	packetCount := len(packets)
	var validationErr error
	for i, packet := range packets {
		if len(packet) > math.MaxUint16 {
			packetCount = i
			validationErr = ErrPacketTooLarge
			break
		}
	}
	if packetCount == 0 {
		return 0, validationErr
	}
	if c.batchWriter != nil {
		packetBuffers := make([]*buf.Buffer, packetCount)
		for i, packet := range packets[:packetCount] {
			packetBuffers[i] = buf.As(packet)
		}
		err := c.batchWriter.WriteConnectedPacketBatch(packetBuffers)
		if err != nil {
			return 0, E.Errors(err, c.connection.Close())
		}
		return packetCount, validationErr
	}
	for i, packet := range packets[:packetCount] {
		_, err := c.connection.Write(packet)
		if err != nil {
			return i, err
		}
	}
	return packetCount, validationErr
}

func (c *datagramPacketConnection) WritePacketBuffers(packetBuffers []*buf.Buffer) (int, error) {
	packetCount := len(packetBuffers)
	var validationErr error
	for i, packetBuffer := range packetBuffers {
		if packetBuffer.Len() > math.MaxUint16 {
			packetCount = i
			validationErr = ErrPacketTooLarge
			break
		}
	}
	if packetCount == 0 {
		buf.ReleaseMulti(packetBuffers)
		return 0, validationErr
	}
	writeBuffers := packetBuffers[:packetCount]
	buf.ReleaseMulti(packetBuffers[packetCount:])
	if c.batchWriter != nil {
		err := c.batchWriter.WriteConnectedPacketBatch(writeBuffers)
		if err != nil {
			return 0, E.Errors(err, c.connection.Close())
		}
		return packetCount, validationErr
	}
	for i, packetBuffer := range writeBuffers {
		_, err := c.connection.Write(packetBuffer.Bytes())
		packetBuffer.Release()
		if err != nil {
			buf.ReleaseMulti(writeBuffers[i+1:])
			return i, err
		}
	}
	return packetCount, validationErr
}

func (c *datagramPacketConnection) SetReadDeadline(deadline time.Time) error {
	return c.connection.SetReadDeadline(deadline)
}

func (c *datagramPacketConnection) SetWriteDeadline(deadline time.Time) error {
	return c.connection.SetWriteDeadline(deadline)
}

func (c *datagramPacketConnection) Close() error {
	return c.connection.Close()
}

func (c *datagramPacketConnection) LocalAddr() net.Addr {
	return c.connection.LocalAddr()
}

func (c *datagramPacketConnection) RemoteAddr() net.Addr {
	return c.connection.RemoteAddr()
}
