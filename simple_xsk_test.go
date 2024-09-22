package xsk

import (
	"sync/atomic"
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

	recvChan, err := simpleXsk.StartRecvChan(1024, -1, nil)
	if err != nil {
		t.Errorf("StartRecvChan failed: %v", err)
	}
	go func() {
		for pkt := range recvChan {
			t.Logf("Received packet: \n%s", HexDump(pkt.Data()))
		}
	}()

	sendChan, err := simpleXsk.StartSendChan(1024, -1, nil)
	if err != nil {
		t.Errorf("StartSendChan failed: %v", err)
	}
	for i := 0; i < 10000; i++ {
		pkt := new(SimplePacket)
		pkt.SetData(make([]byte, 60))
		sendChan <- pkt
	}
	simpleXsk.Close()
	t.Log("TestNewSimpleXsk done")
}

func TestStartRecv(t *testing.T) {
	ifaceName := "ens2"
	queueID := uint32(0)
	config := &SimpleXskConfig{
		NumFrames:   2048,
		FrameSize:   4096,
		LibbpfFlags: 0,
	}
	simpleXsk, err := NewSimpleXsk(ifaceName, queueID, config)
	if err != nil {
		t.Fatalf("NewSimpleXsk failed: %v", err)
	}
	defer simpleXsk.Close()

	pktPool := NewSimplePacketPool()

	recvHandler := func(data []byte) {
		pkt := pktPool.Get()
		pkt.SetData(data)
		t.Logf("Received packet: \n%s", HexDump(pkt.Data()))
		pktPool.Put(pkt)
	}

	err = simpleXsk.StartRecv(1024, -1, recvHandler)
	if err != nil {
		t.Fatalf("StartRecv failed: %v", err)
	}

	// Give some time for the goroutine to start
	time.Sleep(10 * time.Second)

	// Test if another StartRecv returns the correct error
	err = simpleXsk.StartRecv(1024, -1, recvHandler)
	if err != ErrAnotherRecvRunning {
		t.Errorf("Expected ErrAnotherRecvRunning, got: %v", err)
	}

	// Stop the receiver
	simpleXsk.StopRecv()

	// Give some time for the goroutine to stop
	time.Sleep(1 * time.Second)

	// Test if StartRecv works again after stopping
	err = simpleXsk.StartRecv(1024, -1, recvHandler)
	if err != nil {
		t.Errorf("StartRecv failed after stopping: %v", err)
	}

	// Clean up
	simpleXsk.StopRecv()
}

func TestStartRecvSpeed(t *testing.T) {
	pktNum := uint64(0)
	pktBytes := uint64(0)
	ifaceName := "ens2"
	queueID := uint32(0)
	config := &SimpleXskConfig{
		NumFrames:   2048,
		FrameSize:   4096,
		LibbpfFlags: 0,
	}
	simpleXsk, err := NewSimpleXsk(ifaceName, queueID, config)
	if err != nil {
		t.Fatalf("NewSimpleXsk failed: %v", err)
	}
	defer simpleXsk.Close()

	pktPool := NewSimplePacketPool()

	recvHandler := func(data []byte) {
		pkt := pktPool.Get()
		pkt.SetData(data)
		atomic.AddUint64(&pktNum, 1)
		atomic.AddUint64(&pktBytes, uint64(len(pkt.Data())))
		pktPool.Put(pkt)
	}

	err = simpleXsk.StartRecv(1024, -1, recvHandler)
	if err != nil {
		t.Fatalf("StartRecv failed: %v", err)
	}

	go func() {
		for {
			time.Sleep(1 * time.Second)
			pktNum := atomic.SwapUint64(&pktNum, 0)
			pktBytes := atomic.SwapUint64(&pktBytes, 0)
			t.Logf("Received %d packets, %d bytes", pktNum, pktBytes)
		}
	}()

	// Give some time for the goroutine to start
	time.Sleep(10 * time.Second)
}

func TestStartRecvChanSpeed(t *testing.T) {
	pktNum := uint64(0)
	pktBytes := uint64(0)
	ifaceName := "ens2"
	queueID := uint32(0)
	config := &SimpleXskConfig{
		NumFrames:   2048,
		FrameSize:   4096,
		LibbpfFlags: 0,
	}
	simpleXsk, err := NewSimpleXsk(ifaceName, queueID, config)
	if err != nil {
		t.Fatalf("NewSimpleXsk failed: %v", err)
	}
	defer simpleXsk.Close()

	recvChan, err := simpleXsk.StartRecvChan(1024, -1, nil)
	if err != nil {
		t.Fatalf("StartRecv failed: %v", err)
	}

	go func() {
		for pkt := range recvChan {
			atomic.AddUint64(&pktNum, 1)
			atomic.AddUint64(&pktBytes, uint64(len(pkt.Data())))
		}
	}()

	go func() {
		for {
			time.Sleep(1 * time.Second)
			pktNum := atomic.SwapUint64(&pktNum, 0)
			pktBytes := atomic.SwapUint64(&pktBytes, 0)
			t.Logf("Received %d packets, %d bytes", pktNum, pktBytes)
		}
	}()

	// Give some time for the goroutine to start
	time.Sleep(10 * time.Second)
}
func TestStartSendChan(t *testing.T) {
	ifaceName := "ens2"
	queueID := uint32(0)
	config := &SimpleXskConfig{
		NumFrames:   2048,
		FrameSize:   4096,
		LibbpfFlags: XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
	}
	simpleXsk, err := NewSimpleXsk(ifaceName, queueID, config)
	if err != nil {
		t.Fatalf("NewSimpleXsk failed: %v", err)
	}
	defer simpleXsk.Close()

	sendChan, err := simpleXsk.StartSendChan(1024, -1, nil)
	if err != nil {
		t.Fatalf("StartSendChan failed: %v", err)
	}
	pktNum := uint64(0)
	pktBytes := uint64(0)
	stopChan := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopChan:
				return
			default:
				pkt := new(SimplePacket)
				pkt.SetData(make([]byte, 60))
				sendChan <- pkt
				atomic.AddUint64(&pktNum, 1)
				atomic.AddUint64(&pktBytes, uint64(len(pkt.Data())))
			}
		}
	}()
	go func() {
		for {
			time.Sleep(1 * time.Second)
			pktNum := atomic.SwapUint64(&pktNum, 0)
			pktBytes := atomic.SwapUint64(&pktBytes, 0)
			t.Logf("Sent %d packets, %d bytes", pktNum, pktBytes)
		}
	}()
	time.Sleep(10 * time.Second)
	close(stopChan)
	simpleXsk.StopSendChan()
	t.Log("TestStartSendChan done")
}

func TestStartSendChanError(t *testing.T) {
	ifaceName := "ens2"
	queueID := uint32(0)
	config := &SimpleXskConfig{
		NumFrames:   2048,
		FrameSize:   4096,
		LibbpfFlags: XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
	}
	simpleXsk, err := NewSimpleXsk(ifaceName, queueID, config)
	if err != nil {
		t.Fatalf("NewSimpleXsk failed: %v", err)
	}
	defer simpleXsk.Close()

	_, err = simpleXsk.StartSendChan(1024, -1, nil)
	if err != nil {
		t.Fatalf("StartSendChan failed: %v", err)
	}

	_, err = simpleXsk.StartSendChan(1024, -1, nil)
	if err != ErrAnotherSendChanRunning {
		t.Fatalf("Expected ErrAnotherSendChanRunning, got: %v", err)
	}

	simpleXsk.StopSendChan()
	t.Log("TestStartSendChanError done")
}

func TestStartSendChanWithPostProcess(t *testing.T) {
	ifaceName := "ens2"
	queueID := uint32(0)
	config := &SimpleXskConfig{
		NumFrames:   2048,
		FrameSize:   4096,
		LibbpfFlags: XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
	}
	simpleXsk, err := NewSimpleXsk(ifaceName, queueID, config)
	if err != nil {
		t.Fatalf("NewSimpleXsk failed: %v", err)
	}
	defer simpleXsk.Close()

	pktPool := NewSimplePacketPool()
	postProcess := func(pkt Packet) {
		pktPool.Put(pkt)
	}

	sendChan, err := simpleXsk.StartSendChan(1024, -1, postProcess)
	if err != nil {
		t.Fatalf("StartSendChan failed: %v", err)
	}
	pktNum := uint64(0)
	pktBytes := uint64(0)
	stopChan := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopChan:
				return
			default:
				pkt := pktPool.Get()
				pkt.SetData(make([]byte, 60))
				sendChan <- pkt
				atomic.AddUint64(&pktNum, 1)
				atomic.AddUint64(&pktBytes, uint64(len(pkt.Data())))
			}
		}
	}()

	go func() {
		for {
			time.Sleep(1 * time.Second)
			pktNum := atomic.SwapUint64(&pktNum, 0)
			pktBytes := atomic.SwapUint64(&pktBytes, 0)
			t.Logf("Sent %d packets, %d bytes", pktNum, pktBytes)
		}
	}()
	time.Sleep(10 * time.Second)
	close(stopChan)

	simpleXsk.StopSendChan()
	t.Log("TestStartSendChanWithPostProcess done")
}
