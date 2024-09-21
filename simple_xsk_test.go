package xsk

import (
	"testing"
	"time"
)

func TestNewSimpleXsk(t *testing.T) {
	ifaceName := "ens2"
	queueID := uint32(0)
	config := &SimpleXskConfig{
		NumFrames:   2048,
		FrameSize:   4096,
		LibbpfFlags: 0,
	}
	simpleXsk, err := NewSimpleXsk(ifaceName, queueID, config)
	if err != nil {
		t.Errorf("NewSimpleXsk failed: %v", err)
	}

	recvChan := simpleXsk.StartRecv(1024, 0)
	go func() {
		for pkt := range recvChan {
			HexDump(pkt)
		}
	}()

	sendChan := simpleXsk.StartSend(1024, 0)
	for i := 0; i < 10000; i++ {
		sendChan <- []byte("hello world")
	}
	// 测试发送和卸载是否正常，正常就提交
	time.Sleep(5 * time.Second)
	simpleXsk.Close()
	time.Sleep(5 * time.Second)
}
