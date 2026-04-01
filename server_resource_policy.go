package openvpn

import (
	"sync"
	"time"
)

const (
	defaultServerMaxClients                  = 1024
	defaultServerMaxPendingHandshakes        = 100
	defaultServerInitialPacketRate           = 1000
	defaultServerInitialConnectionRate       = 100
	defaultServerInitialConnectionRatePeriod = 10 * time.Second
)

type serverResourcePolicy struct {
	access sync.Mutex

	maxClients              int
	maxPendingHandshakes    int
	initialPacketRate       int
	initialConnectionRate   int
	initialConnectionPeriod time.Duration

	activeAndPending        int
	pending                 int
	windowStart             time.Time
	windowAttempts          int
	packetWindowStart       time.Time
	packetWindowAttempts    int
	challengeWindowStart    time.Time
	challengeWindowAttempts int
}

type serverResourceReservation struct {
	policy      *serverResourcePolicy
	established bool
}

func newServerResourcePolicy(options ServerOptions) *serverResourcePolicy {
	maxClients := options.Resources.MaxClients
	if maxClients == 0 {
		maxClients = defaultServerMaxClients
	}
	maxPendingHandshakes := min(defaultServerMaxPendingHandshakes, maxClients)
	initialConnectionRate := defaultServerInitialConnectionRate
	initialPacketRate := defaultServerInitialPacketRate
	initialConnectionPeriod := defaultServerInitialConnectionRatePeriod
	return &serverResourcePolicy{
		maxClients:              maxClients,
		maxPendingHandshakes:    maxPendingHandshakes,
		initialPacketRate:       initialPacketRate,
		initialConnectionRate:   initialConnectionRate,
		initialConnectionPeriod: initialConnectionPeriod,
	}
}

func (p *serverResourcePolicy) allowInitialPacket(now time.Time) bool {
	p.access.Lock()
	defer p.access.Unlock()
	if p.packetWindowStart.IsZero() || now.Before(p.packetWindowStart) || now.Sub(p.packetWindowStart) >= p.initialConnectionPeriod {
		p.packetWindowStart = now
		p.packetWindowAttempts = 0
	}
	p.packetWindowAttempts++
	return p.packetWindowAttempts <= p.initialPacketRate
}

func (p *serverResourcePolicy) allowInitialChallenge(now time.Time) bool {
	p.access.Lock()
	defer p.access.Unlock()
	if p.challengeWindowStart.IsZero() || now.Before(p.challengeWindowStart) || now.Sub(p.challengeWindowStart) >= p.initialConnectionPeriod {
		p.challengeWindowStart = now
		p.challengeWindowAttempts = 0
	}
	p.challengeWindowAttempts++
	return p.challengeWindowAttempts <= p.initialConnectionRate
}

func (p *serverResourcePolicy) reserve(now time.Time) *serverResourceReservation {
	p.access.Lock()
	defer p.access.Unlock()
	if p.windowStart.IsZero() || now.Before(p.windowStart) || now.Sub(p.windowStart) >= p.initialConnectionPeriod {
		p.windowStart = now
		p.windowAttempts = 0
	}
	p.windowAttempts++
	if p.windowAttempts > p.initialConnectionRate ||
		p.activeAndPending >= p.maxClients ||
		p.pending >= p.maxPendingHandshakes {
		return nil
	}
	p.activeAndPending++
	p.pending++
	return &serverResourceReservation{
		policy: p,
	}
}

func (r *serverResourceReservation) establish() {
	r.policy.access.Lock()
	r.policy.pending--
	r.policy.access.Unlock()
	r.established = true
}

func (r *serverResourceReservation) release() {
	r.policy.access.Lock()
	r.policy.activeAndPending--
	if !r.established {
		r.policy.pending--
	}
	r.policy.access.Unlock()
}
