package openvpn

import (
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type udpPacketWriter struct {
	listener     net.PacketConn
	batchWriter  N.PacketBatchWriter
	destinations []M.Socksaddr
	writeAccess  sync.Mutex
	stateAccess  sync.Mutex
	activePeer   *udpPeerPacketConnection
}

type udpPeerPacketConnection struct {
	writer          *udpPacketWriter
	localAddress    net.Addr
	remoteAccess    sync.RWMutex
	remoteAddress   net.Addr
	readAddress     net.Addr
	readAccess      sync.Mutex
	incomingAccess  sync.Mutex
	incomingPackets *dataPacketQueue[udpPeerPacket]
	closeOnce       sync.Once
	closed          chan struct{}
	deadlineAccess  sync.Mutex
	readDeadline    time.Time
	writeDeadline   time.Time
}

type udpPeerPacket struct {
	buffer        *buf.Buffer
	remoteAddress net.Addr
}

func (c *udpPeerPacketConnection) ReadPacket() ([]byte, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	packets, err := c.waitIncomingPackets(1)
	if err != nil {
		return nil, err
	}
	packet := packets[0]
	c.setReadAddress(packet.remoteAddress)
	payload := append([]byte{}, packet.buffer.Bytes()...)
	packet.buffer.Release()
	packets[0].buffer = nil
	return payload, nil
}

func (c *udpPeerPacketConnection) waitIncomingPackets(maxPackets int) ([]udpPeerPacket, error) {
	for {
		readDeadline, hasDeadline := c.currentReadDeadline()
		var timeout time.Duration
		if hasDeadline {
			timeout = time.Until(readDeadline)
			if timeout <= 0 {
				return nil, os.ErrDeadlineExceeded
			}
		}
		select {
		case <-c.closed:
			return nil, net.ErrClosed
		default:
		}
		packets := c.incomingPackets.Pop(maxPackets, func(firstPacket udpPeerPacket, packet udpPeerPacket) bool {
			return firstPacket.remoteAddress.Network() == packet.remoteAddress.Network() &&
				firstPacket.remoteAddress.String() == packet.remoteAddress.String()
		})
		if len(packets) > 0 {
			return packets, nil
		}
		if hasDeadline {
			timer := time.NewTimer(timeout)
			select {
			case <-c.incomingPackets.Wake():
				timer.Stop()
			case <-c.closed:
				timer.Stop()
				return nil, net.ErrClosed
			case <-timer.C:
				return nil, os.ErrDeadlineExceeded
			}
			continue
		}
		select {
		case <-c.incomingPackets.Wake():
		case <-c.closed:
			return nil, net.ErrClosed
		}
	}
}

func (c *udpPeerPacketConnection) ReadPackets() ([]*buf.Buffer, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	packets, err := c.waitIncomingPackets(dataPacketBatchSize)
	if err != nil {
		return nil, err
	}
	c.setReadAddress(packets[0].remoteAddress)
	packetBuffers := make([]*buf.Buffer, len(packets))
	for i := range packets {
		packetBuffers[i] = packets[i].buffer
	}
	return packetBuffers, nil
}

func (c *udpPeerPacketConnection) WritePacket(packet []byte) error {
	_, err := c.WritePackets([][]byte{packet})
	return err
}

func (c *udpPeerPacketConnection) WritePackets(packets [][]byte) (int, error) {
	return c.writer.writePackets(c, packets)
}

func (c *udpPeerPacketConnection) WritePacketBuffers(packetBuffers []*buf.Buffer) (int, error) {
	return c.writer.writePacketBuffers(c, packetBuffers)
}

func (c *udpPeerPacketConnection) SetReadDeadline(deadline time.Time) error {
	c.deadlineAccess.Lock()
	defer c.deadlineAccess.Unlock()
	c.readDeadline = deadline
	return nil
}

func (c *udpPeerPacketConnection) SetWriteDeadline(deadline time.Time) error {
	return c.writer.setWriteDeadline(c, deadline)
}

func (c *udpPeerPacketConnection) Close() error {
	c.closeOnce.Do(func() {
		c.incomingAccess.Lock()
		close(c.closed)
		c.incomingPackets.Drain(func(packet udpPeerPacket) {
			packet.buffer.Release()
		})
		c.incomingAccess.Unlock()
	})
	return nil
}

func (c *udpPeerPacketConnection) LocalAddr() net.Addr {
	return c.localAddress
}

func (c *udpPeerPacketConnection) RemoteAddr() net.Addr {
	c.remoteAccess.RLock()
	defer c.remoteAccess.RUnlock()
	return c.remoteAddress
}

func (c *udpPeerPacketConnection) pushPackets(packets []udpPeerPacket) uint64 {
	if len(packets) == 0 {
		return 0
	}
	releasePacket := func(packet udpPeerPacket) {
		packet.buffer.Release()
	}
	c.incomingAccess.Lock()
	defer c.incomingAccess.Unlock()
	select {
	case <-c.closed:
		for _, packet := range packets {
			releasePacket(packet)
		}
		return uint64(len(packets))
	default:
	}
	return c.incomingPackets.PushBatchDropNew(packets, releasePacket)
}

func (c *udpPeerPacketConnection) setReadAddress(remoteAddress net.Addr) {
	c.remoteAccess.Lock()
	c.readAddress = remoteAddress
	c.remoteAccess.Unlock()
}

func (c *udpPeerPacketConnection) authenticatedRemoteAddress() net.Addr {
	c.remoteAccess.RLock()
	defer c.remoteAccess.RUnlock()
	return c.readAddress
}

func (c *udpPeerPacketConnection) setRemoteAddress(remoteAddress net.Addr) {
	c.remoteAccess.Lock()
	c.remoteAddress = remoteAddress
	c.remoteAccess.Unlock()
}

func (c *udpPeerPacketConnection) currentReadDeadline() (time.Time, bool) {
	c.deadlineAccess.Lock()
	defer c.deadlineAccess.Unlock()
	return c.readDeadline, !c.readDeadline.IsZero()
}

func (c *udpPeerPacketConnection) currentWriteDeadline() (time.Time, bool) {
	c.deadlineAccess.Lock()
	defer c.deadlineAccess.Unlock()
	return c.writeDeadline, !c.writeDeadline.IsZero()
}

func (w *udpPacketWriter) writePackets(peer *udpPeerPacketConnection, packets [][]byte) (int, error) {
	w.writeAccess.Lock()
	defer w.writeAccess.Unlock()

	w.stateAccess.Lock()
	writeDeadline, hasDeadline := peer.currentWriteDeadline()
	if hasDeadline && !time.Now().Before(writeDeadline) {
		w.stateAccess.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
	w.activePeer = peer
	deadlineErr := w.listener.SetWriteDeadline(writeDeadline)
	w.stateAccess.Unlock()
	if deadlineErr != nil {
		return 0, E.Errors(deadlineErr, w.finishWrite(peer))
	}

	remoteAddress := peer.RemoteAddr()
	if remoteAddress == nil {
		return 0, E.Errors(net.ErrClosed, w.finishWrite(peer))
	}
	if w.batchWriter != nil && len(packets) > 0 {
		packetBuffers := make([]*buf.Buffer, len(packets))
		destination := M.SocksaddrFromNet(remoteAddress)
		destinations := make([]M.Socksaddr, len(packets))
		for i, packet := range packets {
			packetBuffers[i] = buf.As(packet)
			destinations[i] = destination
		}
		writeErr := w.batchWriter.WritePacketBatch(packetBuffers, destinations)
		if writeErr != nil {
			return 0, E.Errors(writeErr, peer.Close(), w.finishWrite(peer))
		}
		return len(packets), w.finishWrite(peer)
	}
	for i, packet := range packets {
		_, writeErr := w.listener.WriteTo(packet, remoteAddress)
		if writeErr != nil {
			return i, E.Errors(writeErr, w.finishWrite(peer))
		}
	}
	return len(packets), w.finishWrite(peer)
}

func (w *udpPacketWriter) writePacketBuffers(peer *udpPeerPacketConnection, packetBuffers []*buf.Buffer) (int, error) {
	w.writeAccess.Lock()
	defer w.writeAccess.Unlock()

	w.stateAccess.Lock()
	writeDeadline, hasDeadline := peer.currentWriteDeadline()
	if hasDeadline && !time.Now().Before(writeDeadline) {
		w.stateAccess.Unlock()
		buf.ReleaseMulti(packetBuffers)
		return 0, os.ErrDeadlineExceeded
	}
	w.activePeer = peer
	deadlineErr := w.listener.SetWriteDeadline(writeDeadline)
	w.stateAccess.Unlock()
	if deadlineErr != nil {
		buf.ReleaseMulti(packetBuffers)
		return 0, E.Errors(deadlineErr, w.finishWrite(peer))
	}

	remoteAddress := peer.RemoteAddr()
	if remoteAddress == nil {
		buf.ReleaseMulti(packetBuffers)
		return 0, E.Errors(net.ErrClosed, w.finishWrite(peer))
	}
	if w.batchWriter != nil && len(packetBuffers) > 0 {
		destination := M.SocksaddrFromNet(remoteAddress)
		destinations := w.destinations
		if cap(destinations) < len(packetBuffers) {
			destinations = make([]M.Socksaddr, len(packetBuffers))
		} else {
			destinations = destinations[:len(packetBuffers)]
		}
		for i := range destinations {
			destinations[i] = destination
		}
		writeErr := w.batchWriter.WritePacketBatch(packetBuffers, destinations)
		clear(destinations)
		w.destinations = destinations[:0]
		if writeErr != nil {
			return 0, E.Errors(writeErr, peer.Close(), w.finishWrite(peer))
		}
		return len(packetBuffers), w.finishWrite(peer)
	}
	for i, packetBuffer := range packetBuffers {
		_, writeErr := w.listener.WriteTo(packetBuffer.Bytes(), remoteAddress)
		packetBuffer.Release()
		if writeErr != nil {
			buf.ReleaseMulti(packetBuffers[i+1:])
			return i, E.Errors(writeErr, w.finishWrite(peer))
		}
	}
	return len(packetBuffers), w.finishWrite(peer)
}

func (w *udpPacketWriter) writePacketTo(packet []byte, remoteAddress net.Addr) error {
	if remoteAddress == nil {
		return net.ErrClosed
	}
	w.writeAccess.Lock()
	defer w.writeAccess.Unlock()

	w.stateAccess.Lock()
	w.activePeer = nil
	deadlineErr := w.listener.SetWriteDeadline(time.Time{})
	w.stateAccess.Unlock()
	if deadlineErr != nil {
		return deadlineErr
	}
	_, writeErr := w.listener.WriteTo(packet, remoteAddress)
	clearErr := w.listener.SetWriteDeadline(time.Time{})
	return E.Errors(writeErr, clearErr)
}

func (w *udpPacketWriter) setWriteDeadline(peer *udpPeerPacketConnection, deadline time.Time) error {
	w.stateAccess.Lock()
	defer w.stateAccess.Unlock()
	peer.deadlineAccess.Lock()
	peer.writeDeadline = deadline
	peer.deadlineAccess.Unlock()
	if w.activePeer != peer {
		return nil
	}
	return w.listener.SetWriteDeadline(deadline)
}

func (w *udpPacketWriter) finishWrite(peer *udpPeerPacketConnection) error {
	w.stateAccess.Lock()
	defer w.stateAccess.Unlock()
	if w.activePeer != peer {
		return nil
	}
	clearErr := w.listener.SetWriteDeadline(time.Time{})
	w.activePeer = nil
	return clearErr
}
