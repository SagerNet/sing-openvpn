package test

import (
	"sync"

	openvpn "github.com/sagernet/sing-openvpn"
	"github.com/sagernet/sing/common/buf"
)

const testOutboundQueueCapacity = 512

type testOutboundQueue struct {
	access  sync.Mutex
	buffers []*buf.Buffer
	closed  bool
	wake    chan struct{}
	done    chan struct{}
	write   func(buffers []*buf.Buffer)
}

func newTestOutboundQueue(write func(buffers []*buf.Buffer)) openvpn.OutboundQueue {
	queue := &testOutboundQueue{
		wake:  make(chan struct{}, 1),
		done:  make(chan struct{}),
		write: write,
	}
	go queue.loop()
	return queue
}

func (q *testOutboundQueue) WriteBuffers(buffers []*buf.Buffer) {
	q.access.Lock()
	if q.closed {
		q.access.Unlock()
		buf.ReleaseMulti(buffers)
		return
	}
	accepted := min(len(buffers), testOutboundQueueCapacity-len(q.buffers))
	q.buffers = append(q.buffers, buffers[:accepted]...)
	q.access.Unlock()
	buf.ReleaseMulti(buffers[accepted:])
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *testOutboundQueue) loop() {
	for {
		q.access.Lock()
		buffers := q.buffers
		q.buffers = nil
		q.access.Unlock()
		if len(buffers) > 0 {
			q.write(buffers)
			continue
		}
		select {
		case <-q.wake:
		case <-q.done:
			return
		}
	}
}

func (q *testOutboundQueue) Close() error {
	q.access.Lock()
	if q.closed {
		q.access.Unlock()
		return nil
	}
	q.closed = true
	pending := q.buffers
	q.buffers = nil
	q.access.Unlock()
	close(q.done)
	buf.ReleaseMulti(pending)
	return nil
}
