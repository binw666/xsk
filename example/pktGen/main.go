package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"time"

	"github.com/binw666/xsk"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func getMonotonicTime() int64 {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return ts.Nano()
}

type frameMeta struct {
	pktLen    uint32
	sendNsOff int32 // absolute offset for 8-byte sendNs, -1 if disabled
}

type flowRuntime struct {
	name      string
	weight    int
	pktLen    uint32
	sendNsOff int32
	templates [][]byte
}

func buildFlowRuntimes(cfg GeneratorConfig) ([]flowRuntime, error) {
	out := make([]flowRuntime, 0, len(cfg.Flows))
	for _, f := range cfg.Flows {
		payload := cfg.Payload
		if f.Payload != nil {
			payload = *f.Payload
		}
		var templates [][]byte
		var sendNsOff int32 = -1
		for i := 0; i < cfg.TemplatesPerFlow; i++ {
			built, err := BuildPacket(f, payload)
			if err != nil {
				return nil, fmt.Errorf("build flow %q template[%d]: %w", f.Name, i, err)
			}
			templates = append(templates, built.Bytes)
			// sendNsOff should be stable across templates within a flow; enforce it.
			if i == 0 {
				sendNsOff = int32(built.SendNsOffset)
				out = append(out, flowRuntime{
					name:      f.Name,
					weight:    f.Weight,
					pktLen:    uint32(f.TotalSize),
					sendNsOff: sendNsOff,
					templates: templates,
				})
			} else if int32(built.SendNsOffset) != sendNsOff {
				return nil, fmt.Errorf("flow %q timestamp offset not stable across templates (%d vs %d)",
					f.Name, built.SendNsOffset, sendNsOff)
			}
		}
		if cfg.TemplatesPerFlow > 0 {
			out[len(out)-1].templates = templates
		}
	}
	return out, nil
}

func buildWeightedSchedule(flows []flowRuntime) ([]int, error) {
	var schedule []int
	for i, f := range flows {
		if f.weight <= 0 {
			return nil, fmt.Errorf("flow %q weight must be >0", f.name)
		}
		for j := 0; j < f.weight; j++ {
			schedule = append(schedule, i)
		}
	}
	if len(schedule) == 0 {
		return nil, fmt.Errorf("no flows to schedule")
	}
	return schedule, nil
}

func main() {
	iface := flag.String("i", "ens1f1", "interface name")
	configPath := flag.String("c", "udp.yaml", "config file path (supports legacy single-flow schema)")
	queueNum := flag.Int("q", 30, "queue quantity")
	rate := flag.Int64("r", 1000, "packet rate (pps, global unless -rate-per-queue); <=0 means unlimited")
	ratePerQueue := flag.Bool("rate-per-queue", false, "treat -r as per-queue pps")
	burst := flag.Int("burst", 2048, "rate limiter burst tokens per queue")
	flag.Parse()
	rand.Seed(time.Now().UnixNano())

	cfg, err := LoadGeneratorConfig(*configPath)
	if err != nil {
		log.Fatalf("Load config failed: %v", err)
	}
	for _, f := range cfg.Flows {
		if f.TotalSize > 2048 {
			log.Fatalf("flow %q total_size=%d exceeds FrameSize=2048", f.Name, f.TotalSize)
		}
	}
	flows, err := buildFlowRuntimes(cfg)
	if err != nil {
		log.Fatalf("Build flows failed: %v", err)
	}
	schedule, err := buildWeightedSchedule(flows)
	if err != nil {
		log.Fatalf("Build schedule failed: %v", err)
	}

	queueHasTS := false
	for i := range flows {
		if flows[i].sendNsOff >= 0 {
			queueHasTS = true
			break
		}
	}

	globalRate := *rate
	var basePerQueue int64
	var remPerQueue int64
	if globalRate > 0 && !*ratePerQueue {
		basePerQueue = globalRate / int64(*queueNum)
		remPerQueue = globalRate % int64(*queueNum)
		if basePerQueue <= 0 {
			basePerQueue = 1
		}
	}

	sendCount := uint64(0)
	sendBytes := uint64(0)
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
		frameSize := 2048
		frameNum := 4096
		metaByFrame := make([]frameMeta, frameNum)

		txDesc := make([]xsk.XDPDesc, 2048)
		for i := 0; i < 2048; i++ {
			txDesc[i] = descs[i]
		}
		rxDesc := make([]xsk.XDPDesc, 2048)
		for i := 0; i < 2048; i++ {
			rxDesc[i] = descs[i+2048]
		}

		nowNs := uint64(getMonotonicTime())
		for j := 0; j < len(txDesc); j++ {
			flowIdx := schedule[(i*len(txDesc)+j)%len(schedule)]
			f := flows[flowIdx]
			template := f.templates[(i+j)%len(f.templates)]
			txDesc[j].Len = f.pktLen

			frameIdx := int(txDesc[j].Addr / uint64(frameSize))
			if frameIdx < 0 || frameIdx >= len(metaByFrame) {
				log.Fatalf("invalid frameIdx=%d addr=%d frameSize=%d", frameIdx, txDesc[j].Addr, frameSize)
			}
			metaByFrame[frameIdx] = frameMeta{
				pktLen:    f.pktLen,
				sendNsOff: f.sendNsOff,
			}

			umem := complexXsk.UmemArea(txDesc[j])
			copy(umem, template)
			if f.sendNsOff >= 0 {
				off := int(f.sendNsOff)
				binary.LittleEndian.PutUint64(umem[off:off+8], nowNs)
			}
		}
		wg.Add(1)

		go func(queueID int, initial []xsk.XDPDesc) {
			defer wg.Done()
			var ratePerQueueValue int64
			if globalRate > 0 {
				if *ratePerQueue {
					ratePerQueueValue = globalRate
				} else {
					ratePerQueueValue = basePerQueue
					if int64(queueID) < remPerQueue {
						ratePerQueueValue++
					}
				}
			}

			pacer := NewTokenBucketPacer(ratePerQueueValue, *burst)
			pending := make([]xsk.XDPDesc, 0, 4096+len(initial))
			pending = append(pending, initial...)
			recyBuf := make([]xsk.XDPDesc, 2048)
			for {
				select {
				case <-ctx.Done():
					complexXsk.Close()
					return
				default:
					complexXsk.Poll(unix.POLLOUT, 0)
					if recy := complexXsk.RecycleCompRingWithBuffer(recyBuf); len(recy) > 0 {
						pending = append(pending, recy...)
					}

					toSend := len(pending)
					if toSend == 0 {
						continue
					}

					allowed := pacer.Take(toSend)
					if allowed == 0 {
						pacer.Sleep()
						continue
					}

					start := toSend - allowed
					batch := pending[start:]

					var nowNs uint64
					if queueHasTS {
						nowNs = uint64(getMonotonicTime())
					}
					var bytesAll uint64
					for k := 0; k < len(batch); k++ {
						frameIdx := int(batch[k].Addr / uint64(frameSize))
						meta := metaByFrame[frameIdx]
						batch[k].Len = meta.pktLen
						if meta.sendNsOff >= 0 {
							umem := complexXsk.UmemArea(batch[k])
							off := int(meta.sendNsOff)
							binary.LittleEndian.PutUint64(umem[off:off+8], nowNs)
						}
						bytesAll += uint64(batch[k].Len)
					}

					rest := complexXsk.PopulateTxRing(batch)
					restLen := len(rest)
					sent := len(batch) - restLen
					// rest is the prefix of batch (PopulateTxRing sends from the end).
					pending = pending[:start+restLen]

					if sent > 0 {
						var bytesSent uint64
						if restLen == 0 {
							bytesSent = bytesAll
						} else {
							var bytesRest uint64
							for i := 0; i < restLen; i++ {
								bytesRest += uint64(batch[i].Len)
							}
							bytesSent = bytesAll - bytesRest
						}
						atomic.AddUint64(&sendCount, uint64(sent))
						atomic.AddUint64(&sendBytes, bytesSent)
					}
				}
			}
		}(i, txDesc)
	}

	go func() {
		for {
			time.Sleep(1 * time.Second)
			sendCount := atomic.SwapUint64(&sendCount, 0)
			sendBytes := atomic.SwapUint64(&sendBytes, 0)
			totalCount += sendCount
			log.Printf("Send rate: %d pps, %d Bps, %d Mbps\n", sendCount, sendBytes, sendBytes>>17)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)
	<-sigs
	log.Println("Received termination signal, cleaning up...")
	cancel()
	wg.Wait()
	log.Printf("Sent %d packets\n", totalCount)
}
