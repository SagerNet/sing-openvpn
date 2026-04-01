package openvpn

import (
	"context"
	"net"
	"net/netip"
	"os"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

const (
	ModeTLS       = "tls"
	ModeStaticKey = "static_key"
)

type PullFilter struct {
	Action string
	Text   string
}

type Remote struct {
	Host     string
	Port     uint16
	Protocol string
}

type TunnelRoute struct {
	Prefix  netip.Prefix
	Gateway netip.Addr
	Metric  int
}

type TunnelConfigurationEventReason string

const (
	TunnelConfigurationEventInitial       TunnelConfigurationEventReason = "initial"
	TunnelConfigurationEventPushUpdate    TunnelConfigurationEventReason = "push_update"
	TunnelConfigurationEventRenegotiation TunnelConfigurationEventReason = "renegotiation"
)

type TunnelConfigurationEvent struct {
	Reason        TunnelConfigurationEventReason
	Configuration TunnelConfiguration
}

type UserPassAuthenticator func(ctx context.Context, username string, password string) error

type ClientTransportOptions struct {
	Remotes            []Remote
	RemoteRandom       bool
	DialContext        func(ctx context.Context, network string, address string) (net.Conn, error)
	Protocol           string
	ExplicitExitNotify uint32
}

type ClientDataChannelOptions struct {
	MTU              uint32
	MSSFix           uint32
	Fragment         uint32
	Cipher           string
	Ciphers          []string
	FallbackCipher   string
	Auth             string
	Compression      string
	CompressionLZO   string
	AllowCompression string
	ReplayWindow     uint32
	PacketHeadroom   int
}

type ClientTLSOptions struct {
	CertificateAuthority Material
	Certificate          Material
	Key                  Material
	Auth                 Material
	Crypt                Material
	CryptV2              Material
	VerifyX509Name       string
	VerifyX509Type       string
	PeerFingerprint      []string
	CRLVerify            string
	RemoteCertificateKU  []string
	RemoteCertificateEKU string
	RemoteCertificateTLS string
	NSCertificateType    string
	VersionMin           string
	VersionMax           string
	CertificateProfile   string
	Cipher               string
	Groups               string
}

type ClientAuthenticationOptions struct {
	Username            string
	Password            string
	AuthRetry           string
	StaticChallenge     string
	StaticChallengeEcho bool
}

type ClientPullOptions struct {
	Enabled     bool
	Filters     []PullFilter
	RouteNoPull bool
}

type ClientTunnelOptions struct {
	DevType              string
	Topology             string
	RedirectGateway      bool
	RedirectGatewayFlags []string
	RedirectPrivate      bool
	RouteMetric          int
	BlockIPv6            bool
	BlockOutsideDNS      bool
	RouteGateway         netip.Addr
	Routes               []TunnelRoute
	DHCPOptions          []string
	LocalAddress         []netip.Prefix
	VPNGateway           netip.Addr
	VPNGatewayIPv6       netip.Addr
}

type ClientTimingOptions struct {
	RenegotiationInterval time.Duration
	RenegotiationBytes    uint64
	RenegotiationPackets  uint64
	PingInterval          time.Duration
	PingRestart           time.Duration
	TLSTimeout            time.Duration
	HandWindow            time.Duration
}

type ClientOptions struct {
	Context               context.Context
	Mode                  string
	Transport             ClientTransportOptions
	DataChannel           ClientDataChannelOptions
	TLS                   ClientTLSOptions
	Authentication        ClientAuthenticationOptions
	Pull                  ClientPullOptions
	Tunnel                ClientTunnelOptions
	Timing                ClientTimingOptions
	StaticKey             Material
	KeyDirection          int
	OnTunnelConfiguration func(event TunnelConfigurationEvent) error
	Logger                logger.ContextLogger
}

type ServerTransportOptions struct {
	ListenAddress string
	Listener      net.Listener
	PacketConn    net.PacketConn
	Protocol      string
}

type ServerResourceOptions struct {
	MaxClients int
}

type ServerDataChannelOptions struct {
	MTU            uint32
	Ciphers        []string
	FallbackCipher string
	Auth           string
	PacketHeadroom int
}

type ServerTLSOptions struct {
	CertificateAuthority    Material
	Certificate             Material
	Key                     Material
	Auth                    Material
	Crypt                   Material
	CryptV2                 Material
	VerifyClientCertificate string
}

type ServerAuthenticationOptions struct {
	Authenticator UserPassAuthenticator
}

type ServerTimingOptions struct {
	RenegotiationInterval time.Duration
}

type ServerTunnelOptions struct {
	AddressPools []netip.Prefix
	Topology     string
	LocalAddress []netip.Prefix
}

type ServerPushOptions struct {
	Routes               []netip.Prefix
	DNS                  []netip.Addr
	BlockOutsideDNS      bool
	PingInterval         time.Duration
	PingRestart          time.Duration
	RedirectGateway      bool
	RedirectGatewayFlags []string
}

type ServerOptions struct {
	Context        context.Context
	Mode           string
	Transport      ServerTransportOptions
	Resources      ServerResourceOptions
	DataChannel    ServerDataChannelOptions
	TLS            ServerTLSOptions
	Authentication ServerAuthenticationOptions
	Timing         ServerTimingOptions
	Tunnel         ServerTunnelOptions
	Push           ServerPushOptions
	KeyDirection   int
	Logger         logger.ContextLogger
}

type TunnelConfiguration struct {
	DevType              string
	Topology             string
	TunMTU               uint32
	LocalIPv4            []netip.Prefix
	LocalIPv6            []netip.Prefix
	VPNGateway           netip.Addr
	VPNGatewayIPv6       netip.Addr
	IPv4Routes           []TunnelRoute
	IPv6Routes           []TunnelRoute
	DNS                  []netip.Addr
	DHCPOptions          []string
	BlockIPv6            bool
	BlockOutsideDNS      bool
	RedirectGateway      bool
	RedirectGatewayFlags []string
	RedirectPrivate      bool
	RouteMetric          int
	RouteGateway         netip.Addr
	PingInterval         time.Duration
	PingRestart          time.Duration
	AuthToken            string
	AuthTokenUser        string
	ExplicitExitNotify   uint32
	PeerID               *uint32
	SelectedCipher       string
	SelectedAuth         string
	ProtocolFlags        []string
	KeyDerivation        string
	InactiveTimeout      time.Duration
	InactiveMinimumBytes uint64
	SessionTimeout       time.Duration
	PingExit             time.Duration
	PingTimerRemote      bool
}

var ErrMaterialSourceConflict = E.New("openvpn material path and content are both set")

type Material struct {
	Path    string
	Content []byte
}

func (m Material) Validate(name string) error {
	if m.Path != "" && len(m.Content) > 0 {
		return E.Extend(ErrMaterialSourceConflict, name)
	}
	return nil
}

func (m Material) IsSet() bool {
	return m.Path != "" || len(m.Content) > 0
}

func loadMaterial(material Material) ([]byte, error) {
	err := material.Validate("material")
	if err != nil {
		return nil, err
	}
	if len(material.Content) > 0 {
		return append([]byte(nil), material.Content...), nil
	}
	if material.Path == "" {
		return nil, nil
	}
	fileContent, err := os.ReadFile(material.Path)
	if err != nil {
		return nil, err
	}
	return fileContent, nil
}
