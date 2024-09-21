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
	pktSize := flag.Int("s", 64, "packet size")
	queueNum := flag.Int("q", 1, "queue quantity")
	rate := flag.Int("r", -1, "packet rate")
	flag.Parse()

	if *queueNum < 1 {
		log.Fatalf("queue quantity must be greater than 0.")
	}

	NumFrames := 4096
	FrameSize := 2048
	sendNum := uint64(0)

	ethChannels, err := xsk.GetEthChannels(*iface)
	if err != nil {
		log.Fatalf("GetEthChannels failed: %v", err)
	}
	maxQueueNum := int(ethChannels.TXCount)
	if maxQueueNum == 0 {
		maxQueueNum = int(ethChannels.CombinedCount)
	}
	if maxQueueNum < *queueNum {
		log.Fatalf("queue quantity must be less than or equal to %d.", maxQueueNum)
	}
	simXsks := make([]*xsk.SimpleXsk, 0, maxQueueNum)
	for queueID := 0; queueID < *queueNum; queueID++ {
		simXsk, err := xsk.NewSimpleXsk(*iface, uint32(queueID), &xsk.SimpleXskConfig{
			NumFrames:   NumFrames,
			FrameSize:   FrameSize,
			LibbpfFlags: xsk.XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		})
		if err != nil {
			log.Fatalf("NewSimpleXsk failed: %v", err)
		}
		simXsks = append(simXsks, simXsk)
		sendChan := simXsk.StartSend(1<<12, -1)
		go func() {
			pkt := make([]byte, *pktSize)
			if *rate > 0 {
				for {
					if pktNum := atomic.LoadUint64(&sendNum); pktNum >= uint64(*rate) {
						continue
					}
					sendChan <- pkt
					atomic.AddUint64(&sendNum, 1)
				}
			} else {
				for {
					sendChan <- pkt
					atomic.AddUint64(&sendNum, 1)
				}
			}
		}()
	}
	// 捕获终止信号
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)

	go func() {
		for {
			pktNum := atomic.SwapUint64(&sendNum, 0)
			pktBytes := pktNum * uint64(*pktSize) * 8
			log.Printf("%d pps %d bps %d mbps", pktNum, pktBytes, pktBytes>>20)
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
