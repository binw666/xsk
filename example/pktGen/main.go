package main

import (
	"flag"
	"log"
	"os"
	"sync/atomic"
	"time"

	"github.com/binw666/xsk"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

func main() {
	iface := flag.String("i", "ens2", "interface name")
	configPath := flag.String("c", "udp.yaml", "config file path")
	queueNum := flag.Int("q", 1, "queue quantity")
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
	sendCount := uint64(0)

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
		defer complexXsk.Close()
		txDesc := make([]xsk.XDPDesc, 2048)
		for i := 0; i < 2048; i++ {
			txDesc[i] = descs[i]
		}
		rxDesc := make([]xsk.XDPDesc, 2048)
		for i := 0; i < 2048; i++ {
			rxDesc[i] = descs[i+2048]
		}
		for i := 0; i < 2048; i++ {
			packet, err := GenerateEthernetPacket(config)
			if err != nil {
				log.Fatalf("Error generating Ethernet packet: %v", err)
			}
			txDesc[i].Len = uint32(config.TotalSize)
			copy(complexXsk.UmemArea(txDesc[i]), packet)
		}
		complexXsk.PopulateTxRing(txDesc)
		go func() {
			for {
				complexXsk.Poll(unix.POLLOUT, -1)
				recyDescs := complexXsk.RecycleCompRing()
				atomic.AddUint64(&sendCount, uint64(len(recyDescs)))
				for i := 0; i < len(recyDescs); i++ {
					recyDescs[i].Len = uint32(config.TotalSize)
				}
				complexXsk.PopulateTxRing(recyDescs)
			}
		}()
	}

	for {
		time.Sleep(1 * time.Second)
		sendCount := atomic.SwapUint64(&sendCount, 0)
		log.Printf("Send %d packets, %d bytes\n", sendCount, sendCount*uint64(config.TotalSize))
	}
}
