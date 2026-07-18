package proto

import (
	"sort"
	"sync"
	"time"
)

const (
	ReliableSendBufferSize          = 6
	ReliableReceiveBufferSize       = 12
	MaximumAcknowledgmentsPerPacket = 4
	AcknowledgmentSetCapacity       = 8
	InitialRetransmissionTimeout    = 2 * time.Second
	MaximumRetransmissionTimeout    = 60 * time.Second
	RecommendedSenderWakeupPeriod   = 60 * time.Second
	FastRetransmissionACKThreshold  = 3
)

type inFlightPacket struct {
	packet                   *Packet
	retransmissionDeadline   time.Time
	higherPacketAcknowledges int
	retransmissionCount      int
}

func (p *inFlightPacket) scheduleForRetransmission(now time.Time) {
	p.retransmissionCount++
	retransmissionInterval := InitialRetransmissionTimeout * time.Duration(1<<max(0, p.retransmissionCount-1))
	retransmissionInterval = min(retransmissionInterval, MaximumRetransmissionTimeout)
	p.retransmissionDeadline = now.Add(retransmissionInterval)
}

type OutgoingReliableState struct {
	access                  sync.Mutex
	inFlightPackets         []*inFlightPacket
	pendingAcknowledgmentID map[PacketID]struct{}
}

func NewOutgoingReliableState() *OutgoingReliableState {
	return &OutgoingReliableState{
		inFlightPackets:         make([]*inFlightPacket, 0, ReliableSendBufferSize),
		pendingAcknowledgmentID: make(map[PacketID]struct{}),
	}
}

func (s *OutgoingReliableState) TryInsertOutgoingPacket(packet *Packet) bool {
	s.access.Lock()
	defer s.access.Unlock()
	if len(s.inFlightPackets) >= ReliableSendBufferSize {
		return false
	}
	s.inFlightPackets = append(s.inFlightPackets, &inFlightPacket{packet: packet})
	sort.SliceStable(s.inFlightPackets, func(leftIndex, rightIndex int) bool {
		return s.inFlightPackets[leftIndex].packet.ID < s.inFlightPackets[rightIndex].packet.ID
	})
	return true
}

func (s *OutgoingReliableState) OnIncomingPacket(packet *Packet) {
	s.access.Lock()
	defer s.access.Unlock()

	if packet.Opcode != OpcodeAcknowledgmentV1 && len(s.pendingAcknowledgmentID) < AcknowledgmentSetCapacity {
		s.pendingAcknowledgmentID[packet.ID] = struct{}{}
	}
	for _, acknowledgedID := range packet.AcknowledgmentIDs {
		for packetIndex := 0; packetIndex < len(s.inFlightPackets); packetIndex++ {
			trackedPacket := s.inFlightPackets[packetIndex]
			if acknowledgedID == trackedPacket.packet.ID {
				lastIndex := len(s.inFlightPackets) - 1
				s.inFlightPackets[packetIndex], s.inFlightPackets[lastIndex] = s.inFlightPackets[lastIndex], s.inFlightPackets[packetIndex]
				s.inFlightPackets = s.inFlightPackets[:lastIndex]
				packetIndex--
				continue
			}
			if acknowledgedID > trackedPacket.packet.ID {
				trackedPacket.higherPacketAcknowledges++
			}
		}
	}
	sort.SliceStable(s.inFlightPackets, func(leftIndex, rightIndex int) bool {
		return s.inFlightPackets[leftIndex].packet.ID < s.inFlightPackets[rightIndex].packet.ID
	})
}

func (s *OutgoingReliableState) NextAcknowledgmentIDs() []PacketID {
	s.access.Lock()
	defer s.access.Unlock()

	acknowledgmentIDs := make([]PacketID, 0, len(s.pendingAcknowledgmentID))
	for pendingID := range s.pendingAcknowledgmentID {
		acknowledgmentIDs = append(acknowledgmentIDs, pendingID)
	}
	sort.SliceStable(acknowledgmentIDs, func(leftIndex, rightIndex int) bool {
		return acknowledgmentIDs[leftIndex] < acknowledgmentIDs[rightIndex]
	})
	if len(acknowledgmentIDs) > MaximumAcknowledgmentsPerPacket {
		acknowledgmentIDs = acknowledgmentIDs[:MaximumAcknowledgmentsPerPacket]
	}
	for _, acknowledgedID := range acknowledgmentIDs {
		delete(s.pendingAcknowledgmentID, acknowledgedID)
	}
	return acknowledgmentIDs
}

func (s *OutgoingReliableState) HasPendingAcknowledgments() bool {
	s.access.Lock()
	defer s.access.Unlock()
	return len(s.pendingAcknowledgmentID) > 0
}

func (s *OutgoingReliableState) HasInFlightPackets() bool {
	s.access.Lock()
	defer s.access.Unlock()
	return len(s.inFlightPackets) > 0
}

func (s *OutgoingReliableState) PacketsReadyToSend(now time.Time) []*Packet {
	s.access.Lock()
	defer s.access.Unlock()

	var readyPackets []*Packet
	for _, readyPacket := range s.inFlightPackets {
		if readyPacket.retransmissionDeadline.IsZero() ||
			!readyPacket.retransmissionDeadline.After(now) ||
			readyPacket.higherPacketAcknowledges >= FastRetransmissionACKThreshold {
			readyPacket.scheduleForRetransmission(now)
			readyPackets = append(readyPackets, readyPacket.packet)
		}
	}
	return readyPackets
}

type IncomingReliableState struct {
	access         sync.Mutex
	pendingPackets []*Packet
	bufferedID     map[PacketID]struct{}
	lastConsumedID PacketID
}

func NewIncomingReliableState() *IncomingReliableState {
	return &IncomingReliableState{
		pendingPackets: make([]*Packet, 0, ReliableReceiveBufferSize),
		bufferedID:     make(map[PacketID]struct{}),
	}
}

func (s *IncomingReliableState) TryInsertIncomingPacket(packet *Packet) bool {
	s.access.Lock()
	defer s.access.Unlock()
	if packet.ID <= s.lastConsumedID {
		return false
	}
	if _, buffered := s.bufferedID[packet.ID]; buffered {
		return false
	}
	nextExpectedID := s.lastConsumedID + 1
	if packet.ID-nextExpectedID >= ReliableReceiveBufferSize {
		return false
	}
	if len(s.pendingPackets) >= ReliableReceiveBufferSize {
		return false
	}
	s.pendingPackets = append(s.pendingPackets, packet)
	s.bufferedID[packet.ID] = struct{}{}
	return true
}

func (s *IncomingReliableState) NextOrderedSequence() []*Packet {
	s.access.Lock()
	defer s.access.Unlock()
	sort.SliceStable(s.pendingPackets, func(leftIndex, rightIndex int) bool {
		return s.pendingPackets[leftIndex].ID < s.pendingPackets[rightIndex].ID
	})

	var readyPackets []*Packet
	var retainedPackets []*Packet
	lastConsumedID := s.lastConsumedID
	for _, packet := range s.pendingPackets {
		if packet.ID == lastConsumedID+1 {
			readyPackets = append(readyPackets, packet)
			delete(s.bufferedID, packet.ID)
			lastConsumedID = packet.ID
			continue
		}
		if packet.ID > lastConsumedID+1 {
			retainedPackets = append(retainedPackets, packet)
		}
	}
	s.pendingPackets = retainedPackets
	s.lastConsumedID = lastConsumedID
	return readyPackets
}
