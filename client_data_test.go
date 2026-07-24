package openvpn

import (
	"testing"

	"github.com/sagernet/sing/common/buf"
)

func TestClientDropsPingAfterDataFraming(t *testing.T) {
	newClient := func() *Client {
		options := ClientOptions{
			DataChannel: ClientDataChannelOptions{
				CompressionLZO: "asym",
				MSSFixDisabled: true,
			},
		}
		client := &Client{
			options: options,
			dataPlane: clientDataPlane{
				incomingDataPackets: newDataPacketQueueWithCapacity[*buf.Buffer](1),
			},
		}
		client.dataPlane.framing.Store(newDataChannelFraming(options, allowCompressionAsymmetric))
		return client
	}
	framedPing := append([]byte{openVPNNoCompressByte}, openVPNDataChannelPingPayload...)

	t.Run("payload", func(t *testing.T) {
		client := newClient()
		client.handleIncomingDataPayloads([][]byte{framedPing}, nil, 0, 0)
		assertNoIncomingDataPackets(t, client)
	})

	t.Run("buffer", func(t *testing.T) {
		client := newClient()
		client.handleIncomingDataBuffers([]*buf.Buffer{newDataPacketBuffer(0, framedPing)}, nil, 0, 0)
		assertNoIncomingDataPackets(t, client)
	})
}

func assertNoIncomingDataPackets(t *testing.T, client *Client) {
	t.Helper()
	packetBuffers := client.dataPlane.incomingDataPackets.Pop(0, nil)
	defer buf.ReleaseMulti(packetBuffers)
	if len(packetBuffers) != 0 {
		t.Fatalf("expected framed keepalive ping to be consumed, got %x", packetBuffers[0].Bytes())
	}
}
