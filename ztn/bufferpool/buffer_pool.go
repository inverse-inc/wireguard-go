package bufferpool

import (
	"sync"
)

var DefaultBufferPool = NewBufferPool()

const maxBufferPoolPktSize = 1500

type BufferPool struct {
	sync.Pool
	sync.Mutex
	aliveBuffers int
}

func NewBufferPool() *BufferPool {
	return &BufferPool{
		Mutex: sync.Mutex{},
		Pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, maxBufferPoolPktSize)
			},
		},
	}
}

func (bp *BufferPool) GetAliveBuffers() int {
	return bp.aliveBuffers
}

func (bp *BufferPool) Get() []byte {
	bp.Lock()
	bp.aliveBuffers++
	bp.Unlock()
	return bp.Pool.Get().([]byte)
}

func (bp *BufferPool) Put(a []byte) {
	bp.Lock()
	bp.aliveBuffers--
	bp.Unlock()
	a = a[:maxBufferPoolPktSize]
	bp.Pool.Put(a)
}
