package main

import (
	"context"
	"encoding/binary"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"time"

	"github.com/binw666/xsk"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

func int64ToBytes(i int64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(i))
	return buf[:]
}

func getMonotonicTime() int64 {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return ts.Nano()
}
func main() {
	iface := flag.String("i", "ens1f1", "interface name")
	configPath := flag.String("c", "udp.yaml", "config file path")
	queueNum := flag.Int("q", 30, "queue quantity")
	rate := flag.Int64("r", 1000, "packet rate")
	flag.Parse()
	// 读取配置文件
	configData, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("Error reading config.yaml: %v", err)
	}

	// 解析配置文件
	var config Config
	err = yaml.Unmarshal(configData, &config)
	if err != nil {
		log.Fatalf("Error parsing config.yaml: %v", err)
	}
	headerSize := GetAllHeaderLength(config)
	sendCount := uint64(0)
	totalCount := uint64(0)
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
				LibbpfFlags: xsk.XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
				XdpFlags:    link.XDPGenericMode,
				BindFlags:   unix.XDP_USE_NEED_WAKEUP,
			},
		})
		if err != nil {
			log.Fatalf("NewComplexXsk failed: %v", err)
		}
		txDesc := make([]xsk.XDPDesc, 2048)
		for i := 0; i < 2048; i++ {
			txDesc[i] = descs[i]
		}
		rxDesc := make([]xsk.XDPDesc, 2048)
		for i := 0; i < 2048; i++ {
			rxDesc[i] = descs[i+2048]
		}
		timeStamp := getMonotonicTime()
		timeStampBytes := int64ToBytes(timeStamp)
		for i := 0; i < 2048; i++ {
			packet, err := GenerateEthernetPacket(config)
			if err != nil {
				log.Fatalf("Error generating Ethernet packet: %v", err)
			}
			txDesc[i].Len = uint32(config.TotalSize)
			if config.Payload.TimeStamp {
				copy(packet[headerSize:], timeStampBytes)
			}
			copy(complexXsk.UmemArea(txDesc[i]), packet)
		}
		complexXsk.PopulateTxRing(txDesc)
		wg.Add(1)

		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					complexXsk.Close()
					return
				default:
					for *rate > int64(0) && atomic.LoadUint64(&sendCount) >= uint64(*rate) {
						time.Sleep(1 * time.Millisecond)
					}
					complexXsk.Poll(unix.POLLOUT, 0)
					recyDescs := complexXsk.RecycleCompRing()
					atomic.AddUint64(&sendCount, uint64(len(recyDescs)))
					if config.Payload.TimeStamp {
						timeStamp := getMonotonicTime()
						timeStampBytes := int64ToBytes(timeStamp)
						for i := 0; i < len(recyDescs); i++ {
							copy(complexXsk.UmemArea(recyDescs[i])[headerSize:], timeStampBytes)
							recyDescs[i].Len = uint32(config.TotalSize)
						}
					} else {
						for i := 0; i < len(recyDescs); i++ {
							recyDescs[i].Len = uint32(config.TotalSize)
						}
					}
					complexXsk.PopulateTxRing(recyDescs)
				}
			}
		}()
	}

	go func() {
		for {
			time.Sleep(1 * time.Second)
			sendCount := atomic.SwapUint64(&sendCount, 0)
			totalCount += sendCount
			log.Printf("Send rate: %d pps, %d Bps, %d Mbps\n", sendCount, sendCount*uint64(config.TotalSize), sendCount*uint64(config.TotalSize)>>17)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)
	<-sigs
	log.Println("Received termination signal, cleaning up...")
	cancel()
	wg.Wait()
	log.Printf("Sent %d packets, %d bytes\n", totalCount, totalCount*uint64(config.TotalSize))
}
