package test

import (
	"net/netip"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
)

type interopStage string

const (
	interopStageP0 interopStage = "P0"
	interopStageP1 interopStage = "P1"
	interopStageP2 interopStage = "P2"
)

type interopDirection string

const (
	interopDirectionClientToRealServer interopDirection = "client_to_real_server"
	interopDirectionRealClientToServer interopDirection = "real_client_to_repo_server"
)

type interopCurrentState string

const (
	interopCurrentPass interopCurrentState = "pass"
	interopCurrentSkip interopCurrentState = "skip"
)

type interopScenario struct {
	Name                    string
	Stage                   interopStage
	Direction               interopDirection
	Current                 interopCurrentState
	SkipReason              string
	Protocol                string
	Mode                    string
	Cipher                  string
	Auth                    string
	DataCiphers             []string
	PeerDataCiphers         []string
	UseAuthUserPass         bool
	UseTLSAuth              bool
	UseTLSCrypt             bool
	UseTLSCryptV2           bool
	TLSCryptV2ForceCookie   bool
	StaticKeyDirectionless  bool
	RouteNoPull             bool
	RenegotiationInterval   time.Duration
	RenegotiationPackets    uint64
	Compression             string
	CompressionLZO          string
	AllowCompression        string
	Fragment                uint32
	MSSFix                  uint32
	ExpectedMSS             uint16
	PushConfiguration       openvpn.TunnelConfiguration
	ExpectedConfiguration   openvpn.TunnelConfiguration
	ExpectEcho              bool
	EchoPayloadSize         int
	ExpectGenerationChange  bool
	ExpectStartErrorContain string
	ExpectClientLogContains []string
	ExpectServerLogContains []string
	RealClientChecks        []string
	Covers                  []string
	LegacyServerMatrix      bool
	MinOpenVPN              string
	MaxOpenVPN              string
}

var openVPNInteropScenarios = []interopScenario{
	{
		Name:               "static_key_udp4_client_to_real_server_echo",
		Stage:              interopStageP1,
		Direction:          interopDirectionClientToRealServer,
		Current:            interopCurrentPass,
		Protocol:           "udp4",
		Mode:               "static_key",
		Cipher:             "AES-256-CBC",
		Auth:               "SHA256",
		ExpectEcho:         true,
		LegacyServerMatrix: true,
		Covers: []string{
			"static_key",
			"static_key_udp4_client_to_real_server",
			"real_data_echo",
		},
	},
	{
		Name:                   "static_key_udp4_directionless_client_to_real_server_echo",
		Stage:                  interopStageP1,
		Direction:              interopDirectionClientToRealServer,
		Current:                interopCurrentPass,
		Protocol:               "udp4",
		Mode:                   "static_key",
		Cipher:                 "AES-256-CBC",
		Auth:                   "SHA256",
		StaticKeyDirectionless: true,
		ExpectEcho:             true,
		LegacyServerMatrix:     true,
		Covers: []string{
			"static_key",
			"static_key_directionless",
			"real_data_echo",
		},
	},
	{
		Name:               "tls_udp4_client_to_real_server_basic",
		Stage:              interopStageP0,
		Direction:          interopDirectionClientToRealServer,
		Current:            interopCurrentPass,
		Protocol:           "udp4",
		Mode:               "tls",
		ExpectEcho:         true,
		LegacyServerMatrix: true,
		Covers:             []string{"tls", "tls_udp4", "p0_client_to_real_server"},
	},
	{
		Name:               "tls_tcp4_client_to_real_server_basic",
		Stage:              interopStageP0,
		Direction:          interopDirectionClientToRealServer,
		Current:            interopCurrentPass,
		Protocol:           "tcp4",
		Mode:               "tls",
		ExpectEcho:         true,
		LegacyServerMatrix: true,
		Covers:             []string{"tls", "tls_tcp4", "p0_client_to_real_server"},
	},
	{
		Name:               "tls_udp4_client_to_real_server_auth_user_pass",
		Stage:              interopStageP0,
		Direction:          interopDirectionClientToRealServer,
		Current:            interopCurrentPass,
		Protocol:           "udp4",
		Mode:               "tls",
		UseAuthUserPass:    true,
		ExpectEcho:         true,
		LegacyServerMatrix: true,
		Covers:             []string{"auth_user_pass", "p0_client_to_real_server"},
	},
	{
		Name:               "tls_udp4_client_to_real_server_tls_auth",
		Stage:              interopStageP0,
		Direction:          interopDirectionClientToRealServer,
		Current:            interopCurrentPass,
		Protocol:           "udp4",
		Mode:               "tls",
		UseTLSAuth:         true,
		ExpectEcho:         true,
		LegacyServerMatrix: true,
		Covers:             []string{"tls_auth", "p0_client_to_real_server"},
	},
	{
		Name:               "tls_udp4_client_to_real_server_tls_crypt",
		Stage:              interopStageP0,
		Direction:          interopDirectionClientToRealServer,
		Current:            interopCurrentPass,
		Protocol:           "udp4",
		Mode:               "tls",
		UseTLSCrypt:        true,
		ExpectEcho:         true,
		LegacyServerMatrix: true,
		Covers:             []string{"tls_crypt", "p0_client_to_real_server"},
	},
	{
		Name:      "tls_udp4_client_to_real_server_push_basic",
		Stage:     interopStageP0,
		Direction: interopDirectionClientToRealServer,
		Current:   interopCurrentPass,
		Protocol:  "udp4",
		Mode:      "tls",
		PushConfiguration: openvpn.TunnelConfiguration{
			Topology:        "subnet",
			TunMTU:          1412,
			LocalIPv4:       []netip.Prefix{netip.MustParsePrefix("10.8.0.2/24")},
			RouteGateway:    netip.MustParseAddr("10.8.0.1"),
			IPv4Routes:      []openvpn.TunnelRoute{{Prefix: netip.MustParsePrefix("10.9.0.0/24")}},
			DNS:             []netip.Addr{netip.MustParseAddr("1.1.1.1")},
			RedirectGateway: true,
		},
		ExpectedConfiguration: openvpn.TunnelConfiguration{
			Topology:        "subnet",
			TunMTU:          1412,
			LocalIPv4:       []netip.Prefix{netip.MustParsePrefix("10.8.0.2/24")},
			RouteGateway:    netip.MustParseAddr("10.8.0.1"),
			IPv4Routes:      []openvpn.TunnelRoute{{Prefix: netip.MustParsePrefix("10.9.0.0/24"), Gateway: netip.MustParseAddr("10.8.0.1")}},
			DNS:             []netip.Addr{netip.MustParseAddr("1.1.1.1")},
			DHCPOptions:     []string{"DNS 1.1.1.1"},
			RedirectGateway: true,
		},
		ExpectEcho: true,
		Covers: []string{
			"push_basic",
			"topology",
			"tun_mtu",
			"route_gateway",
			"route",
			"dhcp_option",
			"redirect_gateway",
		},
	},
	{
		Name:      "tls_udp4_client_to_real_server_push_multisegment",
		Stage:     interopStageP0,
		Direction: interopDirectionClientToRealServer,
		Current:   interopCurrentPass,
		Protocol:  "udp4",
		Mode:      "tls",
		PushConfiguration: openvpn.TunnelConfiguration{
			IPv4Routes: []openvpn.TunnelRoute{
				{Prefix: netip.MustParsePrefix("10.20.0.0/24")},
				{Prefix: netip.MustParsePrefix("10.21.0.0/24")},
				{Prefix: netip.MustParsePrefix("10.22.0.0/24")},
				{Prefix: netip.MustParsePrefix("10.23.0.0/24")},
				{Prefix: netip.MustParsePrefix("10.24.0.0/24")},
				{Prefix: netip.MustParsePrefix("10.25.0.0/24")},
			},
		},
		ExpectedConfiguration: openvpn.TunnelConfiguration{
			IPv4Routes: []openvpn.TunnelRoute{
				{Prefix: netip.MustParsePrefix("10.20.0.0/24"), Gateway: netip.MustParseAddr("10.8.0.1")},
				{Prefix: netip.MustParsePrefix("10.21.0.0/24"), Gateway: netip.MustParseAddr("10.8.0.1")},
				{Prefix: netip.MustParsePrefix("10.22.0.0/24"), Gateway: netip.MustParseAddr("10.8.0.1")},
				{Prefix: netip.MustParsePrefix("10.23.0.0/24"), Gateway: netip.MustParseAddr("10.8.0.1")},
				{Prefix: netip.MustParsePrefix("10.24.0.0/24"), Gateway: netip.MustParseAddr("10.8.0.1")},
				{Prefix: netip.MustParsePrefix("10.25.0.0/24"), Gateway: netip.MustParseAddr("10.8.0.1")},
			},
		},
		ExpectEcho: true,
		Covers:     []string{"push_multisegment"},
	},
	{
		Name:        "tls_udp4_client_to_real_server_route_nopull",
		Stage:       interopStageP0,
		Direction:   interopDirectionClientToRealServer,
		Current:     interopCurrentPass,
		Protocol:    "udp4",
		Mode:        "tls",
		RouteNoPull: true,
		PushConfiguration: openvpn.TunnelConfiguration{
			TunMTU:          1392,
			RouteGateway:    netip.MustParseAddr("10.8.0.1"),
			IPv4Routes:      []openvpn.TunnelRoute{{Prefix: netip.MustParsePrefix("10.9.0.0/24")}},
			DHCPOptions:     []string{"DNS 9.9.9.9"},
			RedirectGateway: true,
		},
		ExpectedConfiguration: openvpn.TunnelConfiguration{
			Topology:    "subnet",
			TunMTU:      1392,
			LocalIPv4:   []netip.Prefix{netip.MustParsePrefix("10.8.0.2/24")},
			IPv4Routes:  []openvpn.TunnelRoute{},
			DNS:         []netip.Addr{netip.MustParseAddr("9.9.9.9")},
			DHCPOptions: []string{"DNS 9.9.9.9"},
		},
		ExpectEcho: true,
		Covers:     []string{"route_nopull"},
	},
	{
		Name:                   "tls_udp4_client_to_real_server_renegotiation",
		Stage:                  interopStageP0,
		Direction:              interopDirectionClientToRealServer,
		Current:                interopCurrentPass,
		SkipReason:             "",
		Protocol:               "udp4",
		Mode:                   "tls",
		RenegotiationInterval:  2 * time.Second,
		RenegotiationPackets:   2,
		ExpectEcho:             true,
		ExpectGenerationChange: true,
		Covers:                 []string{"renegotiation"},
	},
	{
		Name:               "tls_udp4_client_to_real_server_tls_crypt_v2",
		Stage:              interopStageP1,
		Direction:          interopDirectionClientToRealServer,
		Current:            interopCurrentPass,
		SkipReason:         "",
		Protocol:           "udp4",
		Mode:               "tls",
		UseTLSCryptV2:      true,
		ExpectEcho:         true,
		Covers:             []string{"tls_crypt_v2"},
		LegacyServerMatrix: true,
		MinOpenVPN:         "2.5",
	},
	{
		Name:                  "tls_udp4_client_to_real_server_tls_crypt_v2_force_cookie",
		Stage:                 interopStageP1,
		Direction:             interopDirectionClientToRealServer,
		Current:               interopCurrentPass,
		Protocol:              "udp4",
		Mode:                  "tls",
		UseTLSCryptV2:         true,
		TLSCryptV2ForceCookie: true,
		ExpectEcho:            true,
		Covers:                []string{"tls_crypt_v2", "tls_crypt_v2_force_cookie"},
		MinOpenVPN:            "2.6",
	},
	{
		Name:       "tls_udp4_client_to_real_server_ipv6_push",
		Stage:      interopStageP1,
		Direction:  interopDirectionClientToRealServer,
		Current:    interopCurrentPass,
		SkipReason: "",
		Protocol:   "udp4",
		Mode:       "tls",
		PushConfiguration: openvpn.TunnelConfiguration{
			LocalIPv6:  []netip.Prefix{netip.MustParsePrefix("fd00::2/64")},
			IPv6Routes: []openvpn.TunnelRoute{{Prefix: netip.MustParsePrefix("fd10::/64")}},
		},
		ExpectedConfiguration: openvpn.TunnelConfiguration{
			LocalIPv6:      []netip.Prefix{netip.MustParsePrefix("fd00::2/64")},
			VPNGatewayIPv6: netip.MustParseAddr("fd00::1"),
			IPv6Routes:     []openvpn.TunnelRoute{{Prefix: netip.MustParsePrefix("fd10::/64"), Gateway: netip.MustParseAddr("fd00::1")}},
		},
		ExpectEcho: true,
		Covers:     []string{"ipv6_push"},
	},
	{
		Name:            "tls_udp4_client_to_real_server_data_ciphers",
		Stage:           interopStageP1,
		Direction:       interopDirectionClientToRealServer,
		Current:         interopCurrentPass,
		Protocol:        "udp4",
		Mode:            "tls",
		DataCiphers:     []string{"AES-128-GCM"},
		PeerDataCiphers: []string{"AES-256-GCM", "AES-128-GCM"},
		ExpectedConfiguration: openvpn.TunnelConfiguration{
			SelectedCipher: "AES-128-GCM",
		},
		ExpectEcho:              true,
		ExpectServerLogContains: []string{"Outgoing Data Channel: Cipher 'AES-128-GCM'"},
		Covers:                  []string{"data_ciphers"},
	},
	{
		Name:                    "tls_udp4_client_to_real_server_wrong_auth_user_pass",
		Stage:                   interopStageP1,
		Direction:               interopDirectionClientToRealServer,
		Current:                 interopCurrentPass,
		Protocol:                "udp4",
		Mode:                    "tls",
		UseAuthUserPass:         true,
		ExpectStartErrorContain: "auth",
		Covers:                  []string{"negative_bad_auth_user_pass"},
	},
	{
		Name:                    "tls_udp4_client_to_real_server_wrong_ca",
		Stage:                   interopStageP1,
		Direction:               interopDirectionClientToRealServer,
		Current:                 interopCurrentPass,
		Protocol:                "udp4",
		Mode:                    "tls",
		ExpectStartErrorContain: "certificate",
		Covers:                  []string{"negative_bad_ca"},
	},
	{
		Name:                    "tls_udp4_client_to_real_server_wrong_tls_auth",
		Stage:                   interopStageP1,
		Direction:               interopDirectionClientToRealServer,
		Current:                 interopCurrentPass,
		Protocol:                "udp4",
		Mode:                    "tls",
		UseTLSAuth:              true,
		ExpectStartErrorContain: "tls",
		Covers:                  []string{"negative_bad_tls_auth"},
	},
	{
		Name:                    "tls_udp4_client_to_real_server_wrong_tls_crypt",
		Stage:                   interopStageP1,
		Direction:               interopDirectionClientToRealServer,
		Current:                 interopCurrentPass,
		Protocol:                "udp4",
		Mode:                    "tls",
		UseTLSCrypt:             true,
		ExpectStartErrorContain: "tls",
		Covers:                  []string{"negative_bad_tls_crypt"},
	},
	{
		Name:       "tls_udp4_real_client_to_repo_server_basic",
		Stage:      interopStageP0,
		Direction:  interopDirectionRealClientToServer,
		Current:    interopCurrentPass,
		Protocol:   "udp4",
		Mode:       "tls",
		ExpectEcho: true,
		Covers:     []string{"tls", "p0_real_client_to_repo_server"},
	},
	{
		Name:       "tls_tcp4_real_client_to_repo_server_basic",
		Stage:      interopStageP0,
		Direction:  interopDirectionRealClientToServer,
		Current:    interopCurrentPass,
		SkipReason: "",
		Protocol:   "tcp4",
		Mode:       "tls",
		ExpectEcho: true,
		Covers:     []string{"tls", "p0_real_client_to_repo_server"},
	},
	{
		Name:            "tls_udp4_real_client_to_repo_server_auth_user_pass",
		Stage:           interopStageP0,
		Direction:       interopDirectionRealClientToServer,
		Current:         interopCurrentPass,
		SkipReason:      "",
		Protocol:        "udp4",
		Mode:            "tls",
		UseAuthUserPass: true,
		ExpectEcho:      true,
		Covers:          []string{"auth_user_pass", "p0_real_client_to_repo_server"},
	},
	{
		Name:       "tls_udp4_real_client_to_repo_server_tls_auth",
		Stage:      interopStageP0,
		Direction:  interopDirectionRealClientToServer,
		Current:    interopCurrentPass,
		SkipReason: "",
		Protocol:   "udp4",
		Mode:       "tls",
		UseTLSAuth: true,
		ExpectEcho: true,
		Covers:     []string{"tls_auth", "p0_real_client_to_repo_server"},
	},
	{
		Name:        "tls_udp4_real_client_to_repo_server_tls_crypt",
		Stage:       interopStageP0,
		Direction:   interopDirectionRealClientToServer,
		Current:     interopCurrentPass,
		SkipReason:  "",
		Protocol:    "udp4",
		Mode:        "tls",
		UseTLSCrypt: true,
		ExpectEcho:  true,
		Covers:      []string{"tls_crypt", "p0_real_client_to_repo_server"},
	},
	{
		Name:       "tls_udp4_real_client_to_repo_server_push_basic",
		Stage:      interopStageP0,
		Direction:  interopDirectionRealClientToServer,
		Current:    interopCurrentPass,
		SkipReason: "",
		Protocol:   "udp4",
		Mode:       "tls",
		PushConfiguration: openvpn.TunnelConfiguration{
			Topology:        "subnet",
			TunMTU:          1412,
			LocalIPv4:       []netip.Prefix{netip.MustParsePrefix("10.8.0.2/24")},
			RouteGateway:    netip.MustParseAddr("10.8.0.1"),
			IPv4Routes:      []openvpn.TunnelRoute{{Prefix: netip.MustParsePrefix("10.9.0.0/24")}},
			DNS:             []netip.Addr{netip.MustParseAddr("1.1.1.1")},
			RedirectGateway: true,
		},
		ExpectClientLogContains: []string{
			"topology subnet",
			"tun-mtu 1412",
			"ifconfig 10.8.0.2 255.255.255.0",
			"route-gateway 10.8.0.1",
			"route 10.9.0.0 255.255.255.0",
			"dhcp-option DNS 1.1.1.1",
			"redirect-gateway",
		},
		RealClientChecks: []string{
			"ip -o link show dev tun0 | grep -F 'mtu 1412'",
			"ip -o -4 address show dev tun0 | grep -F 'inet 10.8.0.2/24'",
			"ip -4 route show 10.9.0.0/24 | grep -F '10.9.0.0/24 via 10.8.0.1 dev tun0'",
			"ip -4 route show default | grep -F 'default via 10.8.0.1 dev tun0'",
		},
		Covers: []string{"push_basic", "p0_real_client_to_repo_server"},
	},
	{
		Name:      "tls_udp4_real_client_to_repo_server_topology_p2p",
		Stage:     interopStageP0,
		Direction: interopDirectionRealClientToServer,
		Current:   interopCurrentPass,
		Protocol:  "udp4",
		Mode:      "tls",
		PushConfiguration: openvpn.TunnelConfiguration{
			Topology:  "p2p",
			LocalIPv4: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/28")},
		},
		ExpectEcho: true,
		ExpectClientLogContains: []string{
			"topology p2p",
			"ifconfig 10.8.0.4 10.8.0.1",
		},
		RealClientChecks: []string{
			"ip -o -4 address show dev tun0 | grep -F 'inet 10.8.0.4 peer 10.8.0.1/32'",
		},
		Covers: []string{"topology_p2p", "ifconfig_pool_individual", "p0_real_client_to_repo_server"},
	},
	{
		Name:      "tls_udp4_real_client_to_repo_server_topology_net30",
		Stage:     interopStageP0,
		Direction: interopDirectionRealClientToServer,
		Current:   interopCurrentPass,
		Protocol:  "udp4",
		Mode:      "tls",
		PushConfiguration: openvpn.TunnelConfiguration{
			Topology:  "net30",
			LocalIPv4: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/28")},
		},
		ExpectEcho: true,
		ExpectClientLogContains: []string{
			"topology net30",
			"ifconfig 10.8.0.6 10.8.0.5",
		},
		RealClientChecks: []string{
			"ip -o -4 address show dev tun0 | grep -F 'inet 10.8.0.6 peer 10.8.0.5/32'",
		},
		Covers: []string{"topology_net30", "ifconfig_pool_30net", "p0_real_client_to_repo_server"},
	},
	{
		Name:      "tls_udp4_real_client_to_repo_server_push_dns",
		Stage:     interopStageP0,
		Direction: interopDirectionRealClientToServer,
		Current:   interopCurrentPass,
		Protocol:  "udp4",
		Mode:      "tls",
		PushConfiguration: openvpn.TunnelConfiguration{
			DNS: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("2001:4860:4860::8888"),
			},
		},
		ExpectClientLogContains: []string{
			"dhcp-option DNS 1.1.1.1",
			"dhcp-option DNS6 2001:4860:4860::8888",
		},
		Covers: []string{"push_dns", "typed_push_dns", "p0_real_client_to_repo_server"},
	},
	{
		Name:                   "tls_udp4_real_client_to_repo_server_renegotiation",
		Stage:                  interopStageP0,
		Direction:              interopDirectionRealClientToServer,
		Current:                interopCurrentPass,
		SkipReason:             "",
		Protocol:               "udp4",
		Mode:                   "tls",
		RenegotiationInterval:  2 * time.Second,
		RenegotiationPackets:   2,
		ExpectEcho:             true,
		ExpectGenerationChange: true,
		Covers:                 []string{"renegotiation", "p0_real_client_to_repo_server"},
	},
	{
		Name:          "tls_udp4_real_client_to_repo_server_tls_crypt_v2",
		Stage:         interopStageP1,
		Direction:     interopDirectionRealClientToServer,
		Current:       interopCurrentPass,
		SkipReason:    "",
		Protocol:      "udp4",
		Mode:          "tls",
		UseTLSCryptV2: true,
		ExpectEcho:    true,
		Covers:        []string{"tls_crypt_v2", "p1_real_client_to_repo_server"},
	},
	{
		Name:       "tls_udp4_real_client_to_repo_server_ipv6_push",
		Stage:      interopStageP1,
		Direction:  interopDirectionRealClientToServer,
		Current:    interopCurrentPass,
		SkipReason: "",
		Protocol:   "udp4",
		Mode:       "tls",
		PushConfiguration: openvpn.TunnelConfiguration{
			LocalIPv6:  []netip.Prefix{netip.MustParsePrefix("fd00::2/64")},
			IPv6Routes: []openvpn.TunnelRoute{{Prefix: netip.MustParsePrefix("fd10::/64")}},
		},
		ExpectClientLogContains: []string{
			"ifconfig-ipv6 fd00::2/64 fd00::1",
			"route-ipv6 fd10::/64",
		},
		RealClientChecks: []string{
			"ip -o -6 address show dev tun0 | grep -F 'inet6 fd00::2/64'",
			"ip -6 route show fd10::/64 | grep -F 'fd10::/64 dev tun0'",
		},
		Covers: []string{"ipv6_push", "p1_real_client_to_repo_server"},
	},
	{
		Name:                    "tls_udp4_real_client_to_repo_server_data_ciphers",
		Stage:                   interopStageP1,
		Direction:               interopDirectionRealClientToServer,
		Current:                 interopCurrentPass,
		SkipReason:              "",
		Protocol:                "udp4",
		Mode:                    "tls",
		DataCiphers:             []string{"AES-128-GCM"},
		PeerDataCiphers:         []string{"AES-256-GCM", "AES-128-GCM"},
		ExpectEcho:              true,
		ExpectClientLogContains: []string{"Outgoing Data Channel: Cipher 'AES-128-GCM'"},
		Covers:                  []string{"data_ciphers", "p1_real_client_to_repo_server"},
	},
	{
		Name:                    "tls_udp4_real_client_to_repo_server_wrong_auth_user_pass",
		Stage:                   interopStageP1,
		Direction:               interopDirectionRealClientToServer,
		Current:                 interopCurrentPass,
		SkipReason:              "",
		Protocol:                "udp4",
		Mode:                    "tls",
		UseAuthUserPass:         true,
		ExpectStartErrorContain: "auth",
		Covers:                  []string{"negative_bad_auth_user_pass", "p1_real_client_to_repo_server"},
	},
	{
		Name:                    "tls_udp4_real_client_to_repo_server_wrong_tls_auth",
		Stage:                   interopStageP1,
		Direction:               interopDirectionRealClientToServer,
		Current:                 interopCurrentPass,
		SkipReason:              "",
		Protocol:                "udp4",
		Mode:                    "tls",
		UseTLSAuth:              true,
		ExpectStartErrorContain: "tls",
		Covers:                  []string{"negative_bad_tls_auth", "p1_real_client_to_repo_server"},
	},
	{
		Name:                    "tls_udp4_real_client_to_repo_server_wrong_tls_crypt",
		Stage:                   interopStageP1,
		Direction:               interopDirectionRealClientToServer,
		Current:                 interopCurrentPass,
		SkipReason:              "",
		Protocol:                "udp4",
		Mode:                    "tls",
		UseTLSCrypt:             true,
		ExpectStartErrorContain: "tls",
		Covers:                  []string{"negative_bad_tls_crypt", "p1_real_client_to_repo_server"},
	},
	{
		Name:       "static_key_tcp4_client_to_real_server_echo",
		Stage:      interopStageP2,
		Direction:  interopDirectionClientToRealServer,
		Current:    interopCurrentPass,
		SkipReason: "",
		Protocol:   "tcp4",
		Mode:       "static_key",
		Cipher:     "AES-256-CBC",
		Auth:       "SHA256",
		ExpectEcho: true,
		Covers:     []string{"static_key_tcp4"},
	},
	{
		Name:       "tls_udp6_client_to_real_server_basic",
		Stage:      interopStageP2,
		Direction:  interopDirectionClientToRealServer,
		Current:    interopCurrentPass,
		SkipReason: "",
		Protocol:   "udp6",
		Mode:       "tls",
		ExpectEcho: true,
		Covers:     []string{"ipv6_transport"},
	},
	{
		Name:            "tls_udp4_client_to_real_server_fragment",
		Stage:           interopStageP2,
		Direction:       interopDirectionClientToRealServer,
		Current:         interopCurrentPass,
		SkipReason:      "",
		Protocol:        "udp4",
		Mode:            "tls",
		Fragment:        1300,
		ExpectEcho:      true,
		EchoPayloadSize: 1400,
		Covers:          []string{"fragment"},
	},
	{
		Name:        "tls_udp4_client_to_real_server_mssfix",
		Stage:       interopStageP2,
		Direction:   interopDirectionClientToRealServer,
		Current:     interopCurrentPass,
		SkipReason:  "",
		Protocol:    "udp4",
		Mode:        "tls",
		MSSFix:      1200,
		ExpectedMSS: 1136,
		Covers:      []string{"mssfix"},
	},
	{
		Name:             "tls_udp4_client_to_real_server_compression",
		Stage:            interopStageP2,
		Direction:        interopDirectionClientToRealServer,
		Current:          interopCurrentPass,
		SkipReason:       "",
		Protocol:         "udp4",
		Mode:             "tls",
		CompressionLZO:   "yes",
		AllowCompression: "yes",
		ExpectEcho:       true,
		EchoPayloadSize:  1152,
		Covers:           []string{"compression"},
	},
}
