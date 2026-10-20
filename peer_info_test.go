package openvpn

import (
	"strings"
	"testing"
)

func TestBuildTLSPeerInfoOmitsIdentitiesWithoutPushPeerInfo(t *testing.T) {
	peerInfo := buildTLSPeerInfo(ClientOptions{
		PeerUUID:        "202E812C-9B70-56A5-847F-490EBC717053",
		HardwareAddress: "aa:bb:cc:dd:ee:ff",
	}, true)
	if strings.Contains(peerInfo, "UV_UUID=") || strings.Contains(peerInfo, "IV_HWADDR=") {
		t.Fatalf("peer-info unexpectedly included push identities:\n%s", peerInfo)
	}
}

func TestBuildTLSPeerInfoIncludesPushPeerInfoIdentities(t *testing.T) {
	peerInfo := buildTLSPeerInfo(ClientOptions{
		PushPeerInfo:    true,
		PeerUUID:        "202E812C-9B70-56A5-847F-490EBC717053",
		HardwareAddress: "aa:bb:cc:dd:ee:ff",
		DataChannel:     ClientDataChannelOptions{Ciphers: []string{"AES-256-GCM"}},
	}, true)
	if !strings.Contains(peerInfo, "UV_UUID=202E812C-9B70-56A5-847F-490EBC717053\n") {
		t.Fatalf("peer-info missing UV_UUID:\n%s", peerInfo)
	}
	if !strings.Contains(peerInfo, "IV_HWADDR=aa:bb:cc:dd:ee:ff\n") {
		t.Fatalf("peer-info missing IV_HWADDR:\n%s", peerInfo)
	}
	tcpnlIndex := strings.Index(peerInfo, "IV_TCPNL=1\n")
	uuidIndex := strings.Index(peerInfo, "UV_UUID=")
	if tcpnlIndex < 0 || uuidIndex < tcpnlIndex {
		t.Fatalf("push-peer-info identities should follow IV_TCPNL:\n%s", peerInfo)
	}
}

func TestPreparePushPeerInfoIdentitiesGeneratesUUID(t *testing.T) {
	options := ClientOptions{PushPeerInfo: true}
	if err := preparePushPeerInfoIdentities(&options); err != nil {
		t.Fatal(err)
	}
	if options.PeerUUID == "" {
		t.Fatal("expected generated PeerUUID")
	}
	if len(options.PeerUUID) != 36 {
		t.Fatalf("unexpected PeerUUID length: %q", options.PeerUUID)
	}
	if err := preparePushPeerInfoIdentities(&options); err != nil {
		t.Fatal(err)
	}
	firstUUID := options.PeerUUID
	options.PeerUUID = ""
	if err := preparePushPeerInfoIdentities(&options); err != nil {
		t.Fatal(err)
	}
	if options.PeerUUID == firstUUID {
		t.Fatal("expected a new PeerUUID after clearing the previous value")
	}
}

func TestPreparePushPeerInfoIdentitiesRejectsOversizedIdentity(t *testing.T) {
	options := ClientOptions{
		PushPeerInfo: true,
		PeerUUID:     strings.Repeat("a", maxPushPeerInfoIdentityLength+1),
	}
	err := preparePushPeerInfoIdentities(&options)
	if err == nil {
		t.Fatal("expected oversized PeerUUID to be rejected")
	}
}
