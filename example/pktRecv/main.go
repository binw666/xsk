package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/binw666/xsk"
	"golang.org/x/sys/unix"
)

func main() {
	iface := flag.String("i", "ens2", "interface name")
	flag.Parse()
	recvNum := uint64(0)
	recvBytes := uint64(0)
	NumFrames := 4096
	FrameSize := 2048

	ethChannels, err := xsk.GetEthChannels(*iface)
	if err != nil {
		log.Fatalf("GetEthChannels failed: %v", err)
	}
	maxQueueNum := int(ethChannels.TXCount)
	if maxQueueNum == 0 {
		maxQueueNum = int(ethChannels.CombinedCount)
	}

	simXsks := make([]*xsk.SimpleXsk, 0, maxQueueNum)
	for queueID := 0; queueID < maxQueueNum; queueID++ {
		simXsk, err := xsk.NewSimpleXsk(*iface, uint32(queueID), &xsk.SimpleXskConfig{
			NumFrames: NumFrames,
			FrameSize: FrameSize,
		})
		if err != nil {
			log.Fatalf("NewSimpleXsk failed: %v", err)
		}
		simXsks = append(simXsks, simXsk)

		recvChan := simXsk.StartRecv(1<<12, -1)
		go func() {
			for pkt := range recvChan {
				atomic.AddUint64(&recvNum, 1)
				atomic.AddUint64(&recvBytes, uint64(len(pkt)))
			}
		}()
	}

	// 捕获终止信号
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)

	go func() {
		for {
			pktNum := atomic.SwapUint64(&recvNum, 0)
			pktBytes := atomic.SwapUint64(&recvBytes, 0)
			log.Printf("%d pps %d bps %d mbps", pktNum, pktBytes, pktBytes*8>>20)
			time.Sleep(time.Second)
		}
	}()

	// 等待信号
	<-sigs
	log.Println("Received termination signal, cleaning up...")
	for _, simXsk := range simXsks {
		simXsk.Close() // 确保所有的 simXsk 都被关闭
	}
	log.Println("Resources cleaned up, exiting.")
}
