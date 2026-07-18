package openvpn

import (
	"crypto/tls"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-openvpn/proto"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

const tlsControlPayloadSize = 1024

func isControlOrAcknowledgmentOpcode(opcode proto.Opcode) bool {
	return opcode.IsControl() || opcode == proto.OpcodeAcknowledgmentV1
}

type tlsControlProtection struct {
	auth  *controlAuthCodec
	crypt *controlCryptCodec
}

type tlsControlChannel struct {
	packetConnection proto.PacketConnection
	sessionManager   *proto.SessionManager
	protection       tlsControlProtection
	outgoing         *proto.OutgoingReliableState
	incoming         *proto.IncomingReliableState
	onDataPackets    func([]*proto.Packet)
	onHardReset      func(*proto.Packet)
	onSoftReset      func(*proto.Packet)
	wrappedClientKey []byte
	readChunks       chan []byte
	closeOnce        sync.Once
	closed           chan struct{}
	loopWaitGroup    sync.WaitGroup
	readAccess       sync.Mutex
	readRemainder    []byte
	deadlineAccess   sync.Mutex
	readDeadline     time.Time
	writeDeadline    time.Time
	activityAccess   sync.RWMutex
	readActivity     func()
	writeActivity    func()
	tlsAccess        sync.RWMutex
	tlsConnection    *tls.Conn

	// Upstream tls_pre_decrypt keeps every live key_state addressable by
	// key_id.  The root channel remains the sole packet reader and dispatches
	// packets to the reliable/TLS channel which owns that key-id.
	renegotiationAccess   sync.Mutex
	renegotiationChannels map[uint8]*tlsControlChannel
}

func (c *tlsControlChannel) setTLSConnection(connection *tls.Conn) {
	c.tlsAccess.Lock()
	c.tlsConnection = connection
	c.tlsAccess.Unlock()
}

func (c *tlsControlChannel) currentTLSConnection() *tls.Conn {
	c.tlsAccess.RLock()
	defer c.tlsAccess.RUnlock()
	return c.tlsConnection
}

func newTLSControlChannel(
	packetConnection proto.PacketConnection,
	sessionManager *proto.SessionManager,
	protection tlsControlProtection,
	onDataPackets func([]*proto.Packet),
	onHardReset func(*proto.Packet),
	onSoftReset func(*proto.Packet),
) *tlsControlChannel {
	return &tlsControlChannel{
		packetConnection:      packetConnection,
		sessionManager:        sessionManager,
		protection:            protection,
		outgoing:              proto.NewOutgoingReliableState(),
		incoming:              proto.NewIncomingReliableState(),
		onDataPackets:         onDataPackets,
		onHardReset:           onHardReset,
		onSoftReset:           onSoftReset,
		readChunks:            make(chan []byte, 32),
		closed:                make(chan struct{}),
		renegotiationChannels: make(map[uint8]*tlsControlChannel),
	}
}

func (c *tlsControlChannel) registerRenegotiationChannel(keyID uint8, channel *tlsControlChannel) bool {
	if keyID == 0 || keyID > proto.KeyIDMaxValue || channel == nil {
		return false
	}
	readActivity, writeActivity := c.activityObservers()
	channel.setActivityObservers(readActivity, writeActivity)
	c.renegotiationAccess.Lock()
	defer c.renegotiationAccess.Unlock()
	if _, loaded := c.renegotiationChannels[keyID]; loaded {
		return false
	}
	c.renegotiationChannels[keyID] = channel
	return true
}

func (c *tlsControlChannel) setActivityObservers(readActivity func(), writeActivity func()) {
	c.activityAccess.Lock()
	c.readActivity = readActivity
	c.writeActivity = writeActivity
	c.activityAccess.Unlock()
	c.renegotiationAccess.Lock()
	children := make([]*tlsControlChannel, 0, len(c.renegotiationChannels))
	for _, child := range c.renegotiationChannels {
		children = append(children, child)
	}
	c.renegotiationAccess.Unlock()
	for _, child := range children {
		child.setActivityObservers(readActivity, writeActivity)
	}
}

func (c *tlsControlChannel) activityObservers() (func(), func()) {
	c.activityAccess.RLock()
	defer c.activityAccess.RUnlock()
	return c.readActivity, c.writeActivity
}

func (c *tlsControlChannel) markReadActivity() {
	readActivity, _ := c.activityObservers()
	if readActivity != nil {
		readActivity()
	}
}

func (c *tlsControlChannel) markWriteActivity() {
	_, writeActivity := c.activityObservers()
	if writeActivity != nil {
		writeActivity()
	}
}

func (c *tlsControlChannel) unregisterRenegotiationChannel(keyID uint8, channel *tlsControlChannel) {
	c.renegotiationAccess.Lock()
	if c.renegotiationChannels[keyID] == channel {
		delete(c.renegotiationChannels, keyID)
	}
	c.renegotiationAccess.Unlock()
}

func (c *tlsControlChannel) routeToRenegotiationChannel(packet *proto.Packet) bool {
	if packet == nil || packet.KeyID == 0 {
		return false
	}
	c.renegotiationAccess.Lock()
	channel := c.renegotiationChannels[packet.KeyID]
	c.renegotiationAccess.Unlock()
	if channel == nil {
		return false
	}
	channel.processIncomingControlPacket(packet)
	return true
}

func (c *tlsControlChannel) seedIncomingPacket(packet *proto.Packet) {
	if packet == nil {
		return
	}
	if !c.sessionManager.ValidateIncomingRemoteSessionID(packet) {
		return
	}
	c.outgoing.OnIncomingPacket(packet)
}

func (c *tlsControlChannel) Read(buffer []byte) (int, error) {
	for {
		c.readAccess.Lock()
		if len(c.readRemainder) > 0 {
			readCount := copy(buffer, c.readRemainder)
			c.readRemainder = c.readRemainder[readCount:]
			c.readAccess.Unlock()
			return readCount, nil
		}
		c.readAccess.Unlock()

		readDeadline, hasDeadline := c.currentReadDeadline()
		if hasDeadline {
			timeout := time.Until(readDeadline)
			if timeout <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer := time.NewTimer(timeout)
			select {
			case chunk := <-c.readChunks:
				timer.Stop()
				if len(chunk) == 0 {
					continue
				}
				c.readAccess.Lock()
				c.readRemainder = chunk
				c.readAccess.Unlock()
			case <-c.closed:
				timer.Stop()
				return 0, net.ErrClosed
			case <-timer.C:
				return 0, os.ErrDeadlineExceeded
			}
			continue
		}

		select {
		case chunk := <-c.readChunks:
			if len(chunk) == 0 {
				continue
			}
			c.readAccess.Lock()
			c.readRemainder = chunk
			c.readAccess.Unlock()
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
}

func (c *tlsControlChannel) Write(buffer []byte) (int, error) {
	totalWritten := 0
	for len(buffer) > 0 {
		writeDeadline, hasDeadline := c.currentWriteDeadline()
		if hasDeadline && !writeDeadline.IsZero() && time.Now().After(writeDeadline) {
			return totalWritten, os.ErrDeadlineExceeded
		}
		chunkSize := min(len(buffer), tlsControlPayloadSize)
		chunk := append([]byte{}, buffer[:chunkSize]...)
		packet, err := c.sessionManager.NewControlPacket(proto.OpcodeControlV1, chunk)
		if err != nil {
			return totalWritten, err
		}
		for {
			packet.AcknowledgmentIDs = c.outgoing.NextAcknowledgmentIDs()
			if c.outgoing.TryInsertOutgoingPacket(packet) {
				break
			}
			select {
			case <-c.closed:
				return totalWritten, net.ErrClosed
			case <-time.After(10 * time.Millisecond):
			}
			if hasDeadline && !writeDeadline.IsZero() && time.Now().After(writeDeadline) {
				return totalWritten, os.ErrDeadlineExceeded
			}
		}
		err = c.writePacket(packet)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += chunkSize
		buffer = buffer[chunkSize:]
	}
	return totalWritten, nil
}

func (c *tlsControlChannel) waitForReliableDelivery(timeout time.Duration) bool {
	if timeout <= 0 {
		return !c.outgoing.HasInFlightPackets()
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for c.outgoing.HasInFlightPackets() {
		select {
		case <-c.closed:
			return false
		case <-timer.C:
			return false
		case <-ticker.C:
		}
	}
	return true
}

// Upstream session_move_pre_start sends the soft-reset initial_opcode as
// packet ID 0 on the new key_state.
func (c *tlsControlChannel) sendInitialSoftReset() error {
	packet, err := c.sessionManager.NewSoftResetPacket()
	if err != nil {
		return err
	}
	if !c.outgoing.TryInsertOutgoingPacket(packet) {
		return net.ErrClosed
	}
	return c.writePacket(packet)
}

func (c *tlsControlChannel) Close() error {
	c.shutdown()
	c.loopWaitGroup.Wait()
	return nil
}

func (c *tlsControlChannel) LocalAddr() net.Addr {
	return c.packetConnection.LocalAddr()
}

func (c *tlsControlChannel) RemoteAddr() net.Addr {
	return c.packetConnection.RemoteAddr()
}

func (c *tlsControlChannel) SetDeadline(deadline time.Time) error {
	c.deadlineAccess.Lock()
	defer c.deadlineAccess.Unlock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	readErr := c.packetConnection.SetReadDeadline(deadline)
	writeErr := c.packetConnection.SetWriteDeadline(deadline)
	return E.Errors(readErr, writeErr)
}

func (c *tlsControlChannel) SetReadDeadline(deadline time.Time) error {
	c.deadlineAccess.Lock()
	defer c.deadlineAccess.Unlock()
	c.readDeadline = deadline
	return c.packetConnection.SetReadDeadline(deadline)
}

func (c *tlsControlChannel) SetWriteDeadline(deadline time.Time) error {
	c.deadlineAccess.Lock()
	defer c.deadlineAccess.Unlock()
	c.writeDeadline = deadline
	return c.packetConnection.SetWriteDeadline(deadline)
}

func (c *tlsControlChannel) currentReadDeadline() (time.Time, bool) {
	c.deadlineAccess.Lock()
	defer c.deadlineAccess.Unlock()
	return c.readDeadline, !c.readDeadline.IsZero()
}

func (c *tlsControlChannel) currentWriteDeadline() (time.Time, bool) {
	c.deadlineAccess.Lock()
	defer c.deadlineAccess.Unlock()
	return c.writeDeadline, !c.writeDeadline.IsZero()
}

func (c *tlsControlChannel) runReader() {
	defer c.loopWaitGroup.Done()
	for {
		select {
		case <-c.closed:
			return
		default:
		}
		err := c.setNextPacketReadDeadline()
		if err != nil {
			c.shutdown()
			return
		}
		rawPacketBuffers, readErr := c.packetConnection.ReadPackets()
		dataPackets := make([]*proto.Packet, 0, len(rawPacketBuffers))
		dataPacketBuffers := make([]*buf.Buffer, 0, len(rawPacketBuffers))
		flushDataPackets := func() {
			if len(dataPackets) > 0 && c.onDataPackets != nil {
				c.onDataPackets(dataPackets)
			}
			buf.ReleaseMulti(dataPacketBuffers)
			dataPackets = dataPackets[:0]
			dataPacketBuffers = dataPacketBuffers[:0]
		}
		for rawPacketIndex, rawPacketBuffer := range rawPacketBuffers {
			rawPacket := rawPacketBuffer.Bytes()
			if len(rawPacket) == 0 || !proto.Opcode(rawPacket[0]>>3).IsData() {
				flushDataPackets()
			}
			packet, parseErr := c.parseIncomingPacket(rawPacket)
			if parseErr != nil {
				rawPacketBuffer.Release()
				flushDataPackets()
				continue
			}
			if packet.Opcode.IsData() {
				dataPackets = append(dataPackets, packet)
				dataPacketBuffers = append(dataPacketBuffers, rawPacketBuffer)
				continue
			}
			rawPacketBuffer.Release()
			flushDataPackets()
			if c.routeToRenegotiationChannel(packet) {
				continue
			}
			if !c.processIncomingControlPacket(packet) {
				flushDataPackets()
				buf.ReleaseMulti(rawPacketBuffers[rawPacketIndex+1:])
				return
			}
		}
		flushDataPackets()
		if readErr != nil {
			if E.IsTimeout(readErr) {
				continue
			}
			c.shutdown()
			return
		}
	}
}

func (c *tlsControlChannel) setNextPacketReadDeadline() error {
	c.deadlineAccess.Lock()
	defer c.deadlineAccess.Unlock()
	readDeadline := c.readDeadline
	if readDeadline.IsZero() {
		readDeadline = time.Now().Add(time.Second)
	}
	return c.packetConnection.SetReadDeadline(readDeadline)
}

func (c *tlsControlChannel) processIncomingControlPacket(packet *proto.Packet) bool {
	if !c.sessionManager.ValidateIncomingRemoteSessionID(packet) {
		return true
	}
	if isTLSHardResetOpcode(packet.Opcode) {
		if packet.KeyID != 0 || c.sessionManager.CurrentKeyID() != 0 {
			return true
		}
		c.outgoing.OnIncomingPacket(packet)
		c.markReadActivity()
		if c.onHardReset != nil {
			c.onHardReset(packet)
		}
		return true
	}
	if packet.Opcode == proto.OpcodeControlSoftResetV1 {
		if !c.sessionManager.ValidateIncomingLocalSessionID(packet) {
			return true
		}
		if c.onSoftReset != nil {
			c.markReadActivity()
			c.onSoftReset(packet)
		} else {
			c.outgoing.OnIncomingPacket(packet)
			c.markReadActivity()
		}
		return true
	}
	if !c.sessionManager.ValidateIncomingLocalSessionID(packet) {
		return true
	}
	if packet.KeyID != c.sessionManager.CurrentKeyID() {
		return true
	}
	c.outgoing.OnIncomingPacket(packet)
	c.markReadActivity()
	if packet.Opcode == proto.OpcodeAcknowledgmentV1 {
		return true
	}
	if !packet.Opcode.IsControl() {
		return true
	}
	if !c.incoming.TryInsertIncomingPacket(packet) {
		return true
	}
	for _, orderedPacket := range c.incoming.NextOrderedSequence() {
		if len(orderedPacket.Payload) == 0 {
			continue
		}
		payloadCopy := append([]byte{}, orderedPacket.Payload...)
		select {
		case c.readChunks <- payloadCopy:
		case <-c.closed:
			return false
		}
	}
	return true
}

func (c *tlsControlChannel) runSender() {
	defer c.loopWaitGroup.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-c.closed:
			return
		case <-ticker.C:
		}
		now := time.Now()
		for _, packet := range c.outgoing.PacketsReadyToSend(now) {
			writeErr := c.writePacket(packet)
			if writeErr != nil {
				c.shutdown()
				return
			}
		}
		if !c.outgoing.HasPendingAcknowledgments() {
			continue
		}
		acknowledgmentIDs := c.outgoing.NextAcknowledgmentIDs()
		if len(acknowledgmentIDs) == 0 {
			continue
		}
		ackPacket, err := c.newAcknowledgmentPacket(acknowledgmentIDs)
		if err != nil {
			continue
		}
		if ackPacket.Opcode == proto.OpcodeControlWKCv1 && !c.outgoing.TryInsertOutgoingPacket(ackPacket) {
			continue
		}
		err = c.writePacket(ackPacket)
		if err != nil {
			c.shutdown()
			return
		}
	}
}

func (c *tlsControlChannel) newAcknowledgmentPacket(acknowledgmentIDs []proto.PacketID) (*proto.Packet, error) {
	if len(c.wrappedClientKey) > 0 && c.sessionManager.NextLocalControlPacketID() == 1 {
		packet, err := c.sessionManager.NewControlPacket(proto.OpcodeControlWKCv1, nil)
		if err != nil {
			return nil, err
		}
		packet.AcknowledgmentIDs = append([]proto.PacketID(nil), acknowledgmentIDs...)
		return packet, nil
	}
	return c.sessionManager.NewAcknowledgmentPacket(acknowledgmentIDs)
}

func (c *tlsControlChannel) shutdown() {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
}

func (c *tlsControlChannel) writePacket(packet *proto.Packet) error {
	outgoingPacket := packet
	if c.shouldSendWrappedClientKey(packet) && packet.Opcode != proto.OpcodeControlWKCv1 {
		packetCopy := *packet
		packetCopy.Opcode = proto.OpcodeControlWKCv1
		outgoingPacket = &packetCopy
	}
	rawPacket, err := outgoingPacket.Bytes()
	if err != nil {
		return err
	}
	if isControlOrAcknowledgmentOpcode(outgoingPacket.Opcode) {
		if c.protection.crypt != nil {
			rawPacket = c.protection.crypt.encodeControlPacket(rawPacket)
		} else if c.protection.auth != nil {
			rawPacket = c.protection.auth.encodeControlPacket(rawPacket)
		}
	}
	if c.shouldSendWrappedClientKey(outgoingPacket) {
		rawPacket = appendTLSCryptV2WrappedClientKey(rawPacket, c.wrappedClientKey, outgoingPacket.Opcode)
	}
	err = c.packetConnection.WritePacket(rawPacket)
	if err == nil {
		c.markWriteActivity()
	}
	return err
}

func (c *tlsControlChannel) shouldSendWrappedClientKey(packet *proto.Packet) bool {
	if packet == nil || len(c.wrappedClientKey) == 0 || packet.ID != 1 {
		return false
	}
	return packet.Opcode == proto.OpcodeControlV1 || packet.Opcode == proto.OpcodeControlWKCv1
}

func (c *tlsControlChannel) parseIncomingPacket(rawPacket []byte) (*proto.Packet, error) {
	if len(rawPacket) == 0 {
		return nil, E.New("empty packet")
	}
	opcode := proto.Opcode(rawPacket[0] >> 3)
	packetBytes := rawPacket
	if isControlOrAcknowledgmentOpcode(opcode) {
		if c.protection.crypt != nil {
			decodedPacket, decoded := c.protection.crypt.decodeControlPacket(rawPacket)
			if !decoded {
				return nil, E.New("invalid tls-crypt packet")
			}
			packetBytes = decodedPacket
		} else if c.protection.auth != nil {
			decodedPacket, decoded := c.protection.auth.decodeControlPacket(rawPacket)
			if !decoded {
				return nil, E.New("invalid tls-auth packet")
			}
			packetBytes = decodedPacket
		}
	}
	if opcode.IsData() {
		return proto.ParsePacketView(packetBytes)
	}
	return proto.ParsePacket(packetBytes)
}

func isTLSHardResetOpcode(opcode proto.Opcode) bool {
	switch opcode {
	case proto.OpcodeControlHardResetClientV1,
		proto.OpcodeControlHardResetServerV1,
		proto.OpcodeControlHardResetClientV2,
		proto.OpcodeControlHardResetServerV2,
		proto.OpcodeControlHardResetClientV3:
		return true
	default:
		return false
	}
}
