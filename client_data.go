package openvpn

import (
	"context"
	"sync/atomic"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

type clientDataPlane struct {
	framing                    atomic.Pointer[dataChannelFraming]
	incomingPacketDropLog      droppedPacketLog
	allowCompressionPolicy     allowCompressionPolicy
	incomingDataPackets        *dataPacketQueue[*buf.Buffer]
	droppedIncomingDataPackets atomic.Uint64
}

func (c *Client) ReadDataPacket(ctx context.Context) ([]byte, error) {
	packetBuffer, err := c.ReadDataPacketBuffer(ctx)
	if err != nil {
		return nil, err
	}
	payload := append([]byte(nil), packetBuffer.Bytes()...)
	packetBuffer.Release()
	return payload, nil
}

func (c *Client) ReadDataPackets(ctx context.Context) ([]*buf.Buffer, error) {
	return c.readDataPackets(ctx, 0)
}

func (c *Client) ReadDataPacketBuffer(ctx context.Context) (*buf.Buffer, error) {
	packetBuffers, err := c.readDataPackets(ctx, 1)
	if err != nil {
		return nil, err
	}
	return packetBuffers[0], nil
}

func (c *Client) readDataPackets(ctx context.Context, maxPackets int) ([]*buf.Buffer, error) {
	readErr := c.currentDataReadError()
	if readErr != nil {
		return nil, readErr
	}
	for {
		select {
		case <-c.lifecycle.dataReadDone:
			return nil, c.currentDataReadError()
		default:
		}
		packetBuffers := c.dataPlane.incomingDataPackets.Pop(maxPackets, nil)
		if len(packetBuffers) > 0 {
			return packetBuffers, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.lifecycle.dataReadDone:
			return nil, c.currentDataReadError()
		case <-c.dataPlane.incomingDataPackets.Wake():
		}
	}
}

func (c *Client) WriteDataPacket(packet []byte) error {
	return c.WriteDataPackets([][]byte{packet})
}

func (c *Client) WriteDataPackets(packets [][]byte) error {
	if len(packets) == 0 {
		return nil
	}
	session := c.readySession()
	if session == nil {
		return ErrDataChannelNotReady
	}
	return session.WriteDataPackets(packets)
}

func (c *Client) WriteDataPacketBuffers(packetBuffers []*buf.Buffer) error {
	if len(packetBuffers) == 0 {
		return nil
	}
	session := c.readySession()
	if session == nil {
		buf.ReleaseMulti(packetBuffers)
		return ErrDataChannelNotReady
	}
	return session.WriteDataPacketBuffers(packetBuffers)
}

func (c *Client) DroppedIncomingDataPackets() uint64 {
	return c.dataPlane.droppedIncomingDataPackets.Load()
}

func (c *Client) outgoingDataPayloadBatches(payloads [][]byte, codec dataCodec, packetHeaderSize int) ([][][]byte, error) {
	dataFraming := c.dataPlane.framing.Load()
	maximumSegmentSize, err := c.maximumSegmentSize(dataFraming, codec, packetHeaderSize)
	if err != nil {
		return nil, err
	}
	outgoingPayloadBatches := make([][][]byte, 0, len(payloads))
	if dataFraming == nil {
		for _, payload := range payloads {
			clampedPayload := clampTCPSegmentMSS(payload, maximumSegmentSize)
			outgoingPayloadBatches = append(outgoingPayloadBatches, [][]byte{append([]byte{}, clampedPayload...)})
		}
		return outgoingPayloadBatches, nil
	}
	fragmentSize := 0
	if c.options.DataChannel.Fragment > 0 {
		fragmentSize, err = calculateDataPayloadSize(int(c.options.DataChannel.Fragment), codec, packetHeaderSize, 4)
		if err != nil {
			return nil, err
		}
	}
	for _, payload := range payloads {
		clampedPayload := clampTCPSegmentMSS(payload, maximumSegmentSize)
		outgoingPayloads, encodeErr := dataFraming.Encode(clampedPayload, fragmentSize)
		if encodeErr != nil {
			return outgoingPayloadBatches, encodeErr
		}
		outgoingPayloadBatches = append(outgoingPayloadBatches, outgoingPayloads)
	}
	return outgoingPayloadBatches, nil
}

func (c *Client) outgoingDataBufferBatches(payloads []*buf.Buffer, codec dataCodec, packetHeaderSize int) ([][]*buf.Buffer, error) {
	dataFraming := c.dataPlane.framing.Load()
	maximumSegmentSize, err := c.maximumSegmentSize(dataFraming, codec, packetHeaderSize)
	if err != nil {
		buf.ReleaseMulti(payloads)
		return nil, err
	}
	if dataFraming == nil {
		outgoingPayloadBatches := make([][]*buf.Buffer, len(payloads))
		outgoingPayloads := make([]*buf.Buffer, len(payloads))
		for i, payload := range payloads {
			clampTCPSegmentMSS(payload.Bytes(), maximumSegmentSize)
			outgoingPayloads[i] = payload
			outgoingPayloadBatches[i] = outgoingPayloads[i : i+1]
		}
		return outgoingPayloadBatches, nil
	}
	fragmentSize := 0
	if c.options.DataChannel.Fragment > 0 {
		fragmentSize, err = calculateDataPayloadSize(int(c.options.DataChannel.Fragment), codec, packetHeaderSize, 4)
		if err != nil {
			buf.ReleaseMulti(payloads)
			return nil, err
		}
	}
	outgoingPayloadBatches := make([][]*buf.Buffer, 0, len(payloads))
	for i, payload := range payloads {
		clampedPayload := clampTCPSegmentMSS(payload.Bytes(), maximumSegmentSize)
		outgoingPayloads, encodeErr := dataFraming.Encode(clampedPayload, fragmentSize)
		headroom := payload.Start()
		payload.Release()
		if encodeErr != nil {
			buf.ReleaseMulti(payloads[i+1:])
			for _, outgoingPayloadBatch := range outgoingPayloadBatches {
				buf.ReleaseMulti(outgoingPayloadBatch)
			}
			return nil, encodeErr
		}
		outgoingPayloadBuffers := make([]*buf.Buffer, len(outgoingPayloads))
		for j, outgoingPayload := range outgoingPayloads {
			outgoingPayloadBuffer := buf.NewSize(headroom + len(outgoingPayload) + tlsDataAEADTagSize)
			outgoingPayloadBuffer.Resize(headroom, 0)
			_, _ = outgoingPayloadBuffer.Write(outgoingPayload)
			outgoingPayloadBuffers[j] = outgoingPayloadBuffer
		}
		outgoingPayloadBatches = append(outgoingPayloadBatches, outgoingPayloadBuffers)
	}
	return outgoingPayloadBatches, nil
}

func (c *Client) maximumSegmentSize(dataFraming *dataChannelFraming, codec dataCodec, packetHeaderSize int) (uint16, error) {
	if c.options.DataChannel.MSSFix == 0 {
		return 0, nil
	}
	maximumSegmentSize, err := calculateDataPayloadSize(
		int(c.options.DataChannel.MSSFix),
		codec,
		packetHeaderSize,
		ipv4HeaderMinLength+tcpHeaderMinLength+dataFraming.payloadOverhead(),
	)
	if err != nil {
		return 0, err
	}
	return uint16(min(maximumSegmentSize, 1<<16-1)), nil
}

func calculateDataPayloadSize(packetSize int, codec dataCodec, packetHeaderSize int, fixedPayloadSize int) (int, error) {
	if codec == nil || packetSize <= 0 || packetHeaderSize < 0 || fixedPayloadSize < 0 {
		return 0, E.New("invalid data packet budget")
	}
	minimumPacketLength := packetHeaderSize + codec.EncodedLength(fixedPayloadSize)
	if minimumPacketLength >= packetSize {
		return 0, E.New("data packet size is too small for channel overhead")
	}
	minimumPayloadSize := 1
	maximumPayloadSize := packetSize
	for minimumPayloadSize < maximumPayloadSize {
		candidatePayloadSize := minimumPayloadSize + (maximumPayloadSize-minimumPayloadSize+1)/2
		encodedPacketLength := packetHeaderSize + codec.EncodedLength(fixedPayloadSize+candidatePayloadSize)
		if encodedPacketLength <= packetSize {
			minimumPayloadSize = candidatePayloadSize
		} else {
			maximumPayloadSize = candidatePayloadSize - 1
		}
	}
	return minimumPayloadSize, nil
}

func (c *Client) handleIncomingDataPayloads(payloads [][]byte, codec dataCodec, packetHeaderSize int) {
	if len(payloads) == 0 {
		return
	}
	decodedPayloads := make([][]byte, 0, len(payloads))
	var dataFraming *dataChannelFraming
	var maximumSegmentSize uint16
	var framingErr error
	framingInitialized := false
	for _, payload := range payloads {
		currentDataFraming := c.dataPlane.framing.Load()
		if !framingInitialized || currentDataFraming != dataFraming {
			dataFraming = currentDataFraming
			maximumSegmentSize, framingErr = c.maximumSegmentSize(dataFraming, codec, packetHeaderSize)
			framingInitialized = true
		}
		if framingErr != nil {
			continue
		}
		decodedPayload := payload
		if dataFraming != nil {
			var complete bool
			var decodeErr error
			decodedPayload, complete, decodeErr = dataFraming.Decode(payload)
			if decodeErr != nil {
				c.dataPlane.incomingPacketDropLog.Log(decodeErr)
				continue
			}
			if !complete {
				continue
			}
		}
		decodedPayloads = append(decodedPayloads, clampTCPSegmentMSS(decodedPayload, maximumSegmentSize))
	}
	c.pushIncomingDataPackets(decodedPayloads)
}

func (c *Client) handleIncomingDataBuffers(payloads []*buf.Buffer, codec dataCodec, packetHeaderSize int) {
	if len(payloads) == 0 {
		return
	}
	decodedPayloads := make([]*buf.Buffer, 0, len(payloads))
	var dataFraming *dataChannelFraming
	var maximumSegmentSize uint16
	var framingErr error
	framingInitialized := false
	for _, payload := range payloads {
		currentDataFraming := c.dataPlane.framing.Load()
		if !framingInitialized || currentDataFraming != dataFraming {
			dataFraming = currentDataFraming
			maximumSegmentSize, framingErr = c.maximumSegmentSize(dataFraming, codec, packetHeaderSize)
			framingInitialized = true
		}
		if framingErr != nil {
			payload.Release()
			continue
		}
		decodedPayload := payload
		if dataFraming != nil {
			decodedBytes, complete, decodeErr := dataFraming.Decode(payload.Bytes())
			payload.Release()
			if decodeErr != nil {
				c.dataPlane.incomingPacketDropLog.Log(decodeErr)
				continue
			}
			if !complete {
				continue
			}
			decodedPayload = newDataPacketBuffer(c.options.DataChannel.PacketHeadroom, decodedBytes)
		}
		clampTCPSegmentMSS(decodedPayload.Bytes(), maximumSegmentSize)
		decodedPayloads = append(decodedPayloads, decodedPayload)
	}
	c.pushIncomingDataBuffers(decodedPayloads)
}

func newDataPacketBuffer(headroom int, packet []byte) *buf.Buffer {
	if headroom < 0 {
		headroom = 0
	}
	packetBuffer := buf.NewSize(headroom + len(packet))
	packetBuffer.Advance(headroom)
	_, _ = packetBuffer.Write(packet)
	return packetBuffer
}

func (c *Client) pushIncomingDataPackets(packets [][]byte) {
	if len(packets) == 0 {
		return
	}
	packetBuffers := make([]*buf.Buffer, 0, len(packets))
	for _, packet := range packets {
		if len(packet) == 0 {
			continue
		}
		packetBuffers = append(packetBuffers, newDataPacketBuffer(c.options.DataChannel.PacketHeadroom, packet))
	}
	dropped := c.dataPlane.incomingDataPackets.PushBatch(packetBuffers, func(packetBuffer *buf.Buffer) {
		packetBuffer.Release()
	})
	if dropped > 0 {
		c.dataPlane.droppedIncomingDataPackets.Add(dropped)
	}
}

func (c *Client) pushIncomingDataBuffers(packetBuffers []*buf.Buffer) {
	if len(packetBuffers) == 0 {
		return
	}
	dropped := c.dataPlane.incomingDataPackets.PushBatch(packetBuffers, func(packetBuffer *buf.Buffer) {
		packetBuffer.Release()
	})
	if dropped > 0 {
		c.dataPlane.droppedIncomingDataPackets.Add(dropped)
	}
}
