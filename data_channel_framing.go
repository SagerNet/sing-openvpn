package openvpn

import (
	"math/rand/v2"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

type dataChannelFraming struct {
	compressionLZO             bool
	compressionLZOOutbound     bool
	compressionLZOAdaptive     bool
	compressionLZODecompress   bool
	compressionStub            bool
	compressionV2Stub          bool
	compressionLZ4V1           bool
	compressionLZ4V2           bool
	fragmentSize               int
	lzoAdaptiveDisabled        bool
	lzoAdaptiveNext            time.Time
	lzoAdaptiveTotalBytes      int
	lzoAdaptiveCompressedBytes int

	access                   sync.Mutex
	outgoingSequence         int
	incomingBySequence       map[int]*incomingFragmentBuffer
	incomingBytes            int
	incomingSequence         int
	incomingSequenceSet      bool
	reassemblyTimeout        time.Duration
	reassemblyMaxBytes       int
	reassemblyMaxPacketBytes int
}

func newDataChannelFraming(options ClientOptions, allowCompression allowCompressionPolicy) *dataChannelFraming {
	compressionLZO := isLZOCompressionEnabled(options.DataChannel.Compression, options.DataChannel.CompressionLZO)
	compressionLZOName := options.DataChannel.CompressionLZO
	// Upstream compv2_stub_alg / COMP_ALG_LZ4 / COMP_ALGV2_LZ4 define
	// the V2 framing and LZ4 subtype behavior.
	compressionName := options.DataChannel.Compression
	// Upstream options_postprocess_compression maps compress stub to
	// COMP_ALG_STUB | COMP_F_SWAP, using compstub swap framing.
	compressionStub := compressionName == "stub"
	compressionV2Stub := compressionName == "stub-v2"
	compressionLZ4V1 := compressionName == "lz4"
	compressionLZ4V2 := compressionName == "lz4-v2"
	fragmentSize := int(options.DataChannel.Fragment)
	if !compressionLZO && !compressionStub && !compressionV2Stub && !compressionLZ4V1 && !compressionLZ4V2 && fragmentSize <= 0 {
		return nil
	}
	return &dataChannelFraming{
		compressionLZO:           compressionLZO,
		compressionLZOOutbound:   allowCompression == allowCompressionYes && (compressionLZOName == "yes" || compressionLZOName == "adaptive"),
		compressionLZOAdaptive:   compressionLZOName == "adaptive",
		compressionLZODecompress: compressionLZOName == "yes" || compressionLZOName == "adaptive" || compressionLZOName == "asym",
		compressionStub:          compressionStub,
		compressionV2Stub:        compressionV2Stub,
		compressionLZ4V1:         compressionLZ4V1,
		compressionLZ4V2:         compressionLZ4V2,
		fragmentSize:             fragmentSize,
		outgoingSequence:         int(rand.Uint32() & openVPNFragmentSequenceMask),
		incomingBySequence:       make(map[int]*incomingFragmentBuffer),
		reassemblyTimeout:        openVPNFragmentReassemblyTimeout,
		reassemblyMaxBytes:       openVPNFragmentReassemblyMaxBytes,
		reassemblyMaxPacketBytes: openVPNFragmentReassemblyMaxPacketBytes,
	}
}

func (f *dataChannelFraming) payloadOverhead() int {
	if f == nil {
		return 0
	}
	overhead := 0
	if f.compressionLZO || f.compressionStub || f.compressionLZ4V1 {
		overhead++
	}
	if f.fragmentSize > 0 {
		overhead += 4
	}
	return overhead
}

func (f *dataChannelFraming) Encode(payload []byte, fragmentSize int) ([][]byte, error) {
	if f == nil {
		return [][]byte{append([]byte{}, payload...)}, nil
	}

	framedPayload := append([]byte{}, payload...)
	switch {
	case f.compressionStub, f.compressionLZ4V1:
		framedPayload = applyLZ4V1NoCompressFrame(framedPayload)
	case f.compressionLZO:
		framedPayload = f.encodeLZOFrame(framedPayload)
	case f.compressionLZ4V2, f.compressionV2Stub:
		framedPayload = escapeV2StubCompression(framedPayload)
	}

	if f.fragmentSize <= 0 {
		return [][]byte{framedPayload}, nil
	}
	return f.encodeFragments(framedPayload, fragmentSize)
}

func (f *dataChannelFraming) Decode(payload []byte) ([]byte, bool, error) {
	if f == nil {
		return append([]byte{}, payload...), true, nil
	}

	framedPayload := append([]byte{}, payload...)
	if f.fragmentSize > 0 {
		reassembledPayload, complete, err := f.decodeFragment(framedPayload)
		if err != nil || !complete {
			return nil, complete, err
		}
		framedPayload = reassembledPayload
	}

	if f.compressionStub {
		if len(framedPayload) == 0 {
			return nil, false, E.New("missing compression marker")
		}
		// Upstream stub_decompress under COMP_F_SWAP accepts only 0xFB.
		if framedPayload[0] != openVPNNoCompressByteSwap {
			return nil, false, E.New("invalid compression stub marker")
		}
		framedPayload = unswapV1FrameHead(framedPayload)
	} else if f.compressionLZO || f.compressionLZ4V1 {
		if len(framedPayload) == 0 {
			return nil, false, E.New("missing compression marker")
		}
		switch framedPayload[0] {
		case openVPNNoCompressByte:
			framedPayload = framedPayload[1:]
		case openVPNNoCompressByteSwap:
			framedPayload = unswapV1FrameHead(framedPayload)
		case openVPNLZOCompressByte:
			if !f.compressionLZODecompress {
				return nil, false, E.New("compressed lzo payload is not supported")
			}
			decompressedPayload, decompressErr := decompressLZOBlock(framedPayload[1:])
			if decompressErr != nil {
				return nil, false, decompressErr
			}
			framedPayload = decompressedPayload
		case openVPNLZ4CompressByte:
			if !f.compressionLZ4V1 {
				return nil, false, E.New("compressed lz4 payload is not supported")
			}
			decompressedPayload, decompressErr := decompressLZ4V1Frame(framedPayload)
			if decompressErr != nil {
				return nil, false, decompressErr
			}
			framedPayload = decompressedPayload
		default:
			return nil, false, E.New("invalid compression marker")
		}
	} else if f.compressionV2Stub || f.compressionLZ4V2 {
		unwrappedPayload, unwrapErr := f.unwrapV2Compression(framedPayload)
		if unwrapErr != nil {
			return nil, false, unwrapErr
		}
		framedPayload = unwrappedPayload
	}

	return append([]byte{}, framedPayload...), true, nil
}
