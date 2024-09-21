package xsk

import (
	"testing"
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

	recvChan := simpleXsk.StartRecv(1024, -1)
	go func() {
		for pkt := range recvChan {
			HexDump(pkt)
		}
	}()

	sendChan := simpleXsk.StartSend(1024, -1)
	for i := 0; i < 10000; i++ {
		pkt := make([]byte, 60)
		sendChan <- pkt
	}
	simpleXsk.Close()
	t.Log("TestNewSimpleXsk done")
}
