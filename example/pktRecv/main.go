package main

import (
	"context"
	"encoding/binary"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/binw666/xsk"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func GetAllHeaderLength(mode string) int {
	const (
		ethHeaderLen  = 14
		ipHeaderLen   = 20
		tcpHeaderLen  = 20
		udpHeaderLen  = 8
		icmpHeaderLen = 8
	)
	switch strings.ToUpper(mode) {
	case "TCP":
		return ethHeaderLen + ipHeaderLen + tcpHeaderLen
	case "UDP":
		return ethHeaderLen + ipHeaderLen + udpHeaderLen
	case "ICMP":
		return ethHeaderLen + ipHeaderLen + icmpHeaderLen
	default:
		return 0
	}
}
func main() {
	iface := flag.String("i", "ens2", "interface name")
	queueNum := flag.Int("q", 1, "queue quantity")
	mode := flag.String("m", "udp", "mode(udp, tcp, icmp)")
	timeStampEnable := flag.Bool("t", false, "enable timestamp")
	flag.Parse()
	// 分布数组
	dist := make([]uint64, 100000)
	pktSize := GetAllHeaderLength(*mode)
	pktHandler := func(bytes []byte) {
		// dist[0] 原子加
		atomic.AddUint64(&dist[0], 1)
	}
	if *timeStampEnable {
		pktHandler = func(bytes []byte) {
			// 加载时间戳
			timeStamp := bytes[pktSize : pktSize+8]
			// 对比当前时间，计算差值
			now := time.Now().UnixNano()
			diff := now - int64(binary.LittleEndian.Uint64(timeStamp))
			// 换算毫秒单位
			diffMs := diff / 1000000
			if diffMs < 0 {
				diffMs = 0
			} else if diffMs > 99999 {
				diffMs = 99999
			}
			atomic.AddUint64(&dist[diffMs], 1)
		}
	}
	recvCount := uint64(0)
	recvBytes := uint64(0)
	totalCount := uint64(0)
	totalBytes := uint64(0)
	wg := sync.WaitGroup{}
	ctx, cancel := context.WithCancel(context.Background())
	for i := 0; i < *queueNum; i++ {
		complexXsk, descs, err := xsk.NewComplexXsk(*iface, uint32(i), &xsk.ComplexXskConfig{
			UmemConfig: &xsk.ComplexUmemConfig{
				FillSize:      2048,
				CompSize:      2048,
				FrameNum:      4096,
				FrameSize:     2048,
				FrameHeadroom: 0,
				Flags:         0,
			},
			SocketConfig: &xsk.ComplexSocketConfig{
				RxSize:      2048,
				TxSize:      2048,
				LibbpfFlags: 0,
				XdpFlags:    link.XDPGenericMode,
				BindFlags:   unix.XDP_USE_NEED_WAKEUP,
			},
		})
		if err != nil {
			log.Fatalf("NewComplexXsk failed: %v", err)
		}
		rxDesc := make([]xsk.XDPDesc, 2048)
		for i := 0; i < 2048; i++ {
			rxDesc[i] = descs[i]
		}
		txDesc := make([]xsk.XDPDesc, 2048)
		for i := 0; i < 2048; i++ {
			txDesc[i] = descs[i+2048]
		}
		complexXsk.PopulateFillRing(rxDesc)
		wg.Add(1)

		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					complexXsk.Close()
					return
				default:
					complexXsk.Poll(unix.POLLIN, 0)
					recyDescs := complexXsk.RecycleRxRing()
					atomic.AddUint64(&recvCount, uint64(len(recyDescs)))
					for i := 0; i < len(recyDescs); i++ {
						atomic.AddUint64(&recvBytes, uint64(recyDescs[i].Len))
						pktHandler(complexXsk.UmemArea(recyDescs[i]))
					}
					complexXsk.PopulateFillRing(recyDescs)
				}
			}
		}()
	}

	go func() {
		for {
			time.Sleep(1 * time.Second)
			recvCount := atomic.SwapUint64(&recvCount, 0)
			totalCount += recvCount
			recvBytes := atomic.SwapUint64(&recvBytes, 0)
			totalBytes += recvBytes
			log.Printf("Receive rate: %d pps, %d Bps, %d Mbps\n", recvCount, recvBytes, recvBytes>>17)
			if *timeStampEnable {
				for i := 0; i < 100000; i++ {
					if dist[i] > 0 {
						count := atomic.SwapUint64(&dist[i], 0)
						log.Printf("Time diff: %d ms, count: %d\n", i, count)
					}
				}
			}
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)
	<-sigs
	log.Println("Received termination signal, cleaning up...")
	cancel()
	wg.Wait()
	log.Printf("Receive %d packets, %d bytes\n", totalCount, totalBytes)
}
