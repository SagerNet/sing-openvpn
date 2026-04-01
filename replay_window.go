package openvpn

import "sync"

// Upstream DEFAULT_SEQ_BACKTRACK/MAX_SEQ_BACKTRACK bound --replay-window.
const (
	defaultReplayWindowSize = 64
	maxReplayWindowSize     = 65536
)

type replayWindow struct {
	access           sync.Mutex
	windowSize       uint32
	initialized      bool
	highestID        uint32
	highestTimestamp uint32
	bitmap           []uint64
}

// Upstream --replay-window 0 accepts only strictly monotonic packet IDs.
func newReplayWindowWithSize(windowSize uint32) *replayWindow {
	if windowSize > maxReplayWindowSize {
		windowSize = maxReplayWindowSize
	}
	wordCount := int((uint64(windowSize) + 63) / 64)
	if wordCount == 0 {
		wordCount = 1
	}
	return &replayWindow{
		windowSize: windowSize,
		bitmap:     make([]uint64, wordCount),
	}
}

func (w *replayWindow) Accept(packetID uint32) bool {
	if packetID == 0 {
		return false
	}
	w.access.Lock()
	defer w.access.Unlock()
	return w.acceptLocked(packetID)
}

// Upstream packet_id_test rejects long-form timestamp backtracking and
// resets the sequence window when the timestamp advances.
func (w *replayWindow) AcceptLongForm(packetID uint32, timestamp uint32) bool {
	if packetID == 0 {
		return false
	}
	w.access.Lock()
	defer w.access.Unlock()
	if !w.initialized {
		w.initialized = true
		w.highestTimestamp = timestamp
		w.highestID = packetID
		if w.windowSize > 0 {
			w.bitmap[0] = 1
		}
		return true
	}
	if timestamp < w.highestTimestamp {
		return false
	}
	if timestamp > w.highestTimestamp {
		w.highestTimestamp = timestamp
		w.highestID = packetID
		for i := range w.bitmap {
			w.bitmap[i] = 0
		}
		if w.windowSize > 0 {
			w.bitmap[0] = 1
		}
		return true
	}
	return w.acceptLocked(packetID)
}

func (w *replayWindow) acceptLocked(packetID uint32) bool {
	if !w.initialized {
		w.initialized = true
		w.highestID = packetID
		if w.windowSize > 0 {
			w.bitmap[0] = 1
		}
		return true
	}
	if packetID > w.highestID {
		shift := packetID - w.highestID
		if shift >= w.windowSize {
			for i := range w.bitmap {
				w.bitmap[i] = 0
			}
		} else {
			shiftReplayBitmap(w.bitmap, shift)
		}
		if w.windowSize > 0 {
			w.bitmap[0] |= 1
		}
		w.highestID = packetID
		return true
	}
	offset := w.highestID - packetID
	if offset >= w.windowSize {
		return false
	}
	wordIndex := offset / 64
	bitIndex := offset % 64
	packetMask := uint64(1) << bitIndex
	if w.bitmap[wordIndex]&packetMask != 0 {
		return false
	}
	w.bitmap[wordIndex] |= packetMask
	return true
}

func shiftReplayBitmap(bitmap []uint64, shift uint32) {
	wordShift := shift / 64
	bitShift := shift % 64
	wordCount := len(bitmap)
	for targetIndex := wordCount - 1; targetIndex >= 0; targetIndex-- {
		sourceIndex := targetIndex - int(wordShift)
		var result uint64
		if sourceIndex >= 0 {
			result = bitmap[sourceIndex] << bitShift
			if bitShift > 0 && sourceIndex-1 >= 0 {
				result |= bitmap[sourceIndex-1] >> (64 - bitShift)
			}
		}
		bitmap[targetIndex] = result
	}
}
