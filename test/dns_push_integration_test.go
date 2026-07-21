package test

import (
	"context"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
)

func TestModernDNSPushOverridesLegacyDHCPDNSIntegration(t *testing.T) {
	listenAddress := reserveListenAddressForProtocol(t, "udp")
	server, err := openvpn.NewServer(openvpn.ServerOptions{
		Context: context.Background(),
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ServerTransportOptions{
			ListenAddress: listenAddress,
			Protocol:      "udp",
		},
		TLS: openvpn.ServerTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Tunnel: openvpn.ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.94.0.0/24")},
			Topology:     "subnet",
		},
		Push: openvpn.ServerPushOptions{
			DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")},
			DHCPOptions: []string{
				"DOMAIN legacy.example",
				"DOMAIN-SEARCH legacy-search.example",
				"DOMAIN-ROUTE legacy-route.example",
				"WINS 192.0.2.54",
			},
			SearchDomains: []string{"modern-search.example"},
			DNSServers: []openvpn.TunnelDNSServer{
				{
					Priority:       10,
					Addresses:      []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("198.51.100.10"), 0)},
					ResolveDomains: []string{"high.example"},
					Transport:      "doh",
					SNI:            "dns.high.example",
				},
				{
					Priority:       2,
					Addresses:      []netip.AddrPort{netip.MustParseAddrPort("198.51.100.2:5353")},
					ResolveDomains: []string{"low.example"},
					DNSSEC:         "optional",
					Transport:      "dot",
					SNI:            "dns.low.example",
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}
	clientContext, cancelClient := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancelClient)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context:   clientContext,
		Mode:      openvpn.ModeTLS,
		Transport: clientTransportOptions(t, listenAddress, "udp"),
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Pull: openvpn.ClientPullOptions{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	waitForClientReady(t, client, 5*time.Second)
	configuration := waitForClientIfconfig(t, client, 5*time.Second)
	if slices.Contains(configuration.DNS, netip.MustParseAddr("192.0.2.53")) {
		t.Fatalf("legacy DHCP DNS leaked into modern DNS configuration: %v", configuration.DNS)
	}
	if !slices.Equal(configuration.SearchDomains, []string{"modern-search.example"}) {
		t.Fatalf("unexpected modern search domains: %v", configuration.SearchDomains)
	}
	if len(configuration.DNSRoutes) != 0 {
		t.Fatalf("legacy DOMAIN-ROUTE leaked into modern DNS configuration: %v", configuration.DNSRoutes)
	}
	if !slices.Equal(configuration.DHCPOptions, []string{"WINS 192.0.2.54"}) {
		t.Fatalf("legacy DNS-related DHCP options were retained: %v", configuration.DHCPOptions)
	}
	if len(configuration.DNSServers) != 2 || configuration.DNSServers[0].Priority != 2 || configuration.DNSServers[1].Priority != 10 {
		t.Fatalf("unexpected modern DNS servers: %+v", configuration.DNSServers)
	}
	if configuration.DNSServers[0].Transport != "dot" || configuration.DNSServers[1].Transport != "doh" {
		t.Fatalf("unexpected modern DNS transports: %+v", configuration.DNSServers)
	}
}

func TestModernDNSSearchOnlyKeepsLegacyDHCPResolverIntegration(t *testing.T) {
	listenAddress := reserveListenAddressForProtocol(t, "udp")
	legacyResolver := netip.MustParseAddr("192.0.2.60")
	server, err := openvpn.NewServer(openvpn.ServerOptions{
		Context: context.Background(),
		Mode:    openvpn.ModeTLS,
		Transport: openvpn.ServerTransportOptions{
			ListenAddress: listenAddress,
			Protocol:      "udp",
		},
		TLS: openvpn.ServerTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "server.key")},
		},
		Tunnel: openvpn.ServerTunnelOptions{
			AddressPools: []netip.Prefix{netip.MustParsePrefix("10.95.0.0/24")},
			Topology:     "subnet",
		},
		Push: openvpn.ServerPushOptions{
			DNS:           []netip.Addr{legacyResolver},
			DHCPOptions:   []string{"DOMAIN legacy.example"},
			SearchDomains: []string{"modern.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}
	clientContext, cancelClient := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancelClient)
	client, err := openvpn.NewClient(openvpn.ClientOptions{
		Context:   clientContext,
		Mode:      openvpn.ModeTLS,
		Transport: clientTransportOptions(t, listenAddress, "udp"),
		TLS: openvpn.ClientTLSOptions{
			CertificateAuthority: openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "ca.crt")},
			Certificate:          openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.crt")},
			Key:                  openvpn.Material{Path: filepath.Join("testdata", "openvpn", "pki", "client.key")},
		},
		Pull: openvpn.ClientPullOptions{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	waitForClientReady(t, client, 5*time.Second)
	configuration := waitForClientIfconfig(t, client, 5*time.Second)
	if !slices.Equal(configuration.DNS, []netip.Addr{legacyResolver}) {
		t.Fatalf("search-only modern DNS removed legacy resolver: %v", configuration.DNS)
	}
	if !slices.Equal(configuration.SearchDomains, []string{"modern.example", "legacy.example"}) {
		t.Fatalf("search-only modern DNS did not append legacy search domain: %v", configuration.SearchDomains)
	}
}
