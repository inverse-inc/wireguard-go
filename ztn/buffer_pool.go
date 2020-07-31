package ztn

import "sync"

var defaultBufferPool = NewBufferPool()

type BufferPool struct {
	sync.Pool
}

func NewBufferPool() *BufferPool {
	return &BufferPool{
		Pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 1024)
			},
		},
	}
}

func (bp *BufferPool) Get() []byte {
	return bp.Pool.Get().([]byte)
}

func (bp *BufferPool) Put(a []byte) {
	a = a[:1024]
	bp.Pool.Put(a)
}
