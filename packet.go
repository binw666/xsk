package xsk

import (
	"errors"
)

const (
	MaxPacketDataSize = 2048
	FrameHeadroom     = 64
	FrameTailroom     = 0
	PacketRawDataSize = FrameHeadroom + MaxPacketDataSize + FrameTailroom
)

type PacketRawData [PacketRawDataSize]byte

type Packet interface {
	// Data 返回数据包中有效的数据部分。数据不应被修改。
	Data() []byte
	// Len 返回数据包的当前长度。
	Len() int
	// SetData 将提供的数据复制到数据包并更新长度。(如果容量不足，则返回错误)
	SetData([]byte) error
}

// SimplePacket 表示具有原始数据和数据字节切片的基本数据包结构。
// 它还维护用于数据操作的头部和尾部索引。
//
// 字段:
// - rawData: 数据包的原始数据。
// - data:    保存数据包数据的字节切片。
// - head:    表示数据开始的整数索引。
// - tail:    表示数据结束的整数索引。
type SimplePacket struct {
	rawData PacketRawData
	data    []byte
	head    int
	tail    int
}

// Data 返回数据包中有效的数据部分。数据不应被修改。
func (p *SimplePacket) Data() []byte {
	return p.data
}

// Len 返回数据包的当前长度。
func (p *SimplePacket) Len() int {
	return len(p.data)
}

// SetData 将提供的数据复制到数据包并更新长度。
// 如果数据超过 MaxPacketDataSize，则返回错误。
func (p *SimplePacket) SetData(data []byte) error {
	if len(data) > MaxPacketDataSize {
		return errors.New("data too large")
	}
	copy(p.rawData[FrameHeadroom:], data)
	p.head = FrameHeadroom
	p.tail = FrameHeadroom + len(data)
	p.data = p.rawData[p.head:p.tail]
	return nil
}

// RunHandler 执行提供的处理函数，该函数接收指向 SimplePacket 的 PacketRawData、head 和 tail 的指针。
// 在处理函数执行后，它会更新 SimplePacket 的 data 字段，使其成为从 head 到 tail 的 rawData 切片。
//
// 参数:
//
//	handler - 一个函数，接收指向 PacketRawData、head 和 tail 的指针，并对它们执行操作。
func (p *SimplePacket) RunHandler(handler func(*PacketRawData, *int, *int)) {
	handler(&p.rawData, &p.head, &p.tail)
	p.data = p.rawData[p.head:p.tail]
}
