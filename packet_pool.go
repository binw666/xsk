package xsk

import "sync"

type PacketPool interface {
	Get() Packet
	Put(Packet)
}

type SimplePacketPool struct {
	pool *sync.Pool
}

func NewSimplePacketPool() *SimplePacketPool {
	return &SimplePacketPool{
		pool: &sync.Pool{
			New: func() interface{} {
				return &SimplePacket{}
			},
		},
	}
}

func (p *SimplePacketPool) Get() Packet {
	return p.pool.Get().(*SimplePacket)
}

func (p *SimplePacketPool) Put(packet Packet) {
	p.pool.Put(packet)
}
