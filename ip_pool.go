package openvpn

import (
	"net/netip"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	ipv4TopologySubnet = "subnet"
	ipv4TopologyP2P    = "p2p"
	ipv4TopologyNet30  = "net30"
)

type ipv4PoolLease struct {
	Client netip.Addr
	Peer   netip.Addr
}

type ipPool struct {
	access       sync.Mutex
	ipv4Prefix   netip.Prefix
	ipv4Topology string
	ipv4Server   netip.Addr
	ipv4Start    netip.Addr
	ipv4End      netip.Addr
	ipv4UsedSet  map[netip.Addr]struct{}
	ipv6Prefix   netip.Prefix
	ipv6Server   netip.Addr
	ipv6UsedSet  map[netip.Addr]struct{}
}

func newIPPool(addressPools []netip.Prefix, topology string) (*ipPool, error) {
	resolvedTopology, err := resolveIPv4PoolTopology(topology)
	if err != nil {
		return nil, err
	}
	pool := &ipPool{
		ipv4Topology: resolvedTopology,
		ipv4UsedSet:  make(map[netip.Addr]struct{}),
		ipv6UsedSet:  make(map[netip.Addr]struct{}),
	}
	for _, prefix := range addressPools {
		if !prefix.IsValid() {
			continue
		}
		prefix = prefix.Masked()
		if !prefix.Addr().Is4() || pool.ipv4Prefix.IsValid() {
			continue
		}
		err = pool.configureIPv4(prefix)
		if err != nil {
			return nil, err
		}
	}
	for _, prefix := range addressPools {
		if !prefix.IsValid() {
			continue
		}
		prefix = prefix.Masked()
		if !prefix.Addr().Is6() || pool.ipv6Prefix.IsValid() {
			continue
		}
		pool.ipv6Prefix = prefix
		pool.ipv6Server = prefix.Masked().Addr().Next()
		pool.ipv6UsedSet[pool.ipv6Server] = struct{}{}
	}
	return pool, nil
}

func resolveIPv4PoolTopology(topology string) (string, error) {
	if topology == "" {
		return ipv4TopologyNet30, nil
	}
	switch topology {
	case ipv4TopologySubnet, ipv4TopologyP2P, ipv4TopologyNet30:
		return topology, nil
	default:
		return "", E.New("unsupported IPv4 topology: ", topology)
	}
}

func (p *ipPool) configureIPv4(prefix netip.Prefix) error {
	// OpenVPN's --server helper accepts at most 65536 addresses and requires
	// enough room for its server endpoints plus a client pool.
	if prefix.Bits() < 16 || prefix.Bits() > 29 {
		return E.New("OpenVPN IPv4 address pool must be between /16 and /29: ", prefix)
	}
	network := prefix.Masked().Addr()
	broadcast := lastIPv4InPrefix(prefix)
	p.ipv4Prefix = prefix
	p.ipv4Server = prefix.Masked().Addr().Next()
	switch p.ipv4Topology {
	case ipv4TopologySubnet:
		p.ipv4Start = addIPv4(network, 2)
		p.ipv4End = addIPv4(broadcast, -1)
	case ipv4TopologyP2P, ipv4TopologyNet30:
		// This mirrors helper.c: the first /30 is reserved for the server
		// interface.  OpenVPN also reserves the last four addresses except for
		// the smallest accepted (/29) network.
		p.ipv4Start = addIPv4(network, 4)
		poolEndReserve := int64(4)
		if prefix.Bits() == 29 {
			poolEndReserve = 0
		}
		p.ipv4End = addIPv4(broadcast, -poolEndReserve)
	}
	if !p.ipv4Start.IsValid() || !p.ipv4End.IsValid() || p.ipv4Start.Compare(p.ipv4End) > 0 {
		return E.New("OpenVPN IPv4 address pool has no allocatable addresses: ", prefix)
	}
	return nil
}

func (p *ipPool) HasIPv4() bool {
	return p.ipv4Prefix.IsValid()
}

func (p *ipPool) HasIPv6() bool {
	return p.ipv6Prefix.IsValid()
}

func (p *ipPool) ServerIPv4() netip.Addr {
	return p.ipv4Server
}

func (p *ipPool) ServerIPv6() netip.Addr {
	return p.ipv6Server
}

func (p *ipPool) SetServerIPv4(address netip.Addr) error {
	if !address.IsValid() {
		return nil
	}
	if !address.Is4() || !p.ipv4Prefix.Contains(address) {
		return E.New("server IPv4 address ", address, " is outside pool ", p.ipv4Prefix)
	}
	if address == p.ipv4Prefix.Masked().Addr() || address == lastIPv4InPrefix(p.ipv4Prefix) {
		return E.New("server IPv4 address ", address, " is not a usable host in pool ", p.ipv4Prefix)
	}
	p.access.Lock()
	defer p.access.Unlock()
	if len(p.ipv4UsedSet) > 0 {
		return E.New("cannot change server IPv4 address after allocating client addresses")
	}
	p.ipv4Server = address
	return nil
}

func (p *ipPool) SetServerIPv6(address netip.Addr) error {
	if !address.IsValid() {
		return nil
	}
	if !address.Is6() || !p.ipv6Prefix.Contains(address) {
		return E.New("server IPv6 address ", address, " is outside pool ", p.ipv6Prefix)
	}
	p.access.Lock()
	defer p.access.Unlock()
	delete(p.ipv6UsedSet, p.ipv6Server)
	p.ipv6Server = address
	p.ipv6UsedSet[address] = struct{}{}
	return nil
}

func (p *ipPool) IPv4Prefix() netip.Prefix {
	return p.ipv4Prefix
}

func (p *ipPool) IPv4Topology() string {
	return p.ipv4Topology
}

func (p *ipPool) IPv6Prefix() netip.Prefix {
	return p.ipv6Prefix
}

func (p *ipPool) AllocateIPv4() (ipv4PoolLease, error) {
	if !p.HasIPv4() {
		return ipv4PoolLease{}, E.New("ipv4 pool not configured")
	}
	p.access.Lock()
	defer p.access.Unlock()
	switch p.ipv4Topology {
	case ipv4TopologySubnet, ipv4TopologyP2P:
		for client := p.ipv4Start; client.IsValid() && client.Compare(p.ipv4End) <= 0; client = client.Next() {
			if client == p.ipv4Server {
				continue
			}
			if _, used := p.ipv4UsedSet[client]; used {
				continue
			}
			lease := ipv4PoolLease{Client: client}
			if p.ipv4Topology == ipv4TopologyP2P {
				lease.Peer = p.ipv4Server
			}
			p.ipv4UsedSet[client] = struct{}{}
			return lease, nil
		}
	case ipv4TopologyNet30:
		for block := p.ipv4Start; block.IsValid() && block.Compare(p.ipv4End) <= 0; block = addIPv4(block, 4) {
			peer := addIPv4(block, 1)
			client := addIPv4(block, 2)
			if !peer.IsValid() || !client.IsValid() || client.Compare(p.ipv4End) > 0 {
				break
			}
			if peer == p.ipv4Server || client == p.ipv4Server {
				continue
			}
			if _, used := p.ipv4UsedSet[client]; used {
				continue
			}
			p.ipv4UsedSet[client] = struct{}{}
			return ipv4PoolLease{Client: client, Peer: peer}, nil
		}
	}
	return ipv4PoolLease{}, ErrIPPoolExhausted
}

func (p *ipPool) AllocateIPv6() (netip.Addr, error) {
	if !p.HasIPv6() {
		return netip.Addr{}, E.New("ipv6 pool not configured")
	}
	p.access.Lock()
	defer p.access.Unlock()
	prefix := p.ipv6Prefix
	current := prefix.Addr()
	for {
		current = current.Next()
		if !current.IsValid() || !prefix.Contains(current) {
			return netip.Addr{}, ErrIPPoolExhausted
		}
		if current == p.ipv6Server {
			continue
		}
		_, used := p.ipv6UsedSet[current]
		if used {
			continue
		}
		p.ipv6UsedSet[current] = struct{}{}
		return current, nil
	}
}

func (p *ipPool) Release(address netip.Addr) {
	if !address.IsValid() {
		return
	}
	p.access.Lock()
	defer p.access.Unlock()
	if address.Is4() {
		delete(p.ipv4UsedSet, address)
		return
	}
	delete(p.ipv6UsedSet, address)
}

func lastIPv4InPrefix(prefix netip.Prefix) netip.Addr {
	maskedAddress := prefix.Masked().Addr().As4()
	hostBits := 32 - prefix.Bits()
	if hostBits <= 0 {
		return prefix.Addr()
	}
	last := uint32(maskedAddress[0])<<24 | uint32(maskedAddress[1])<<16 | uint32(maskedAddress[2])<<8 | uint32(maskedAddress[3])
	last |= (uint32(1) << hostBits) - 1
	var lastBytes [4]byte
	lastBytes[0] = byte(last >> 24)
	lastBytes[1] = byte(last >> 16)
	lastBytes[2] = byte(last >> 8)
	lastBytes[3] = byte(last)
	return netip.AddrFrom4(lastBytes)
}

func addIPv4(address netip.Addr, offset int64) netip.Addr {
	if !address.Is4() {
		return netip.Addr{}
	}
	bytes := address.As4()
	value := int64(uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3]))
	value += offset
	if value < 0 || value > int64(^uint32(0)) {
		return netip.Addr{}
	}
	result := uint32(value)
	return netip.AddrFrom4([4]byte{byte(result >> 24), byte(result >> 16), byte(result >> 8), byte(result)})
}
