package xsk

import (
	"container/list"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type SimpleXsk struct {
	umem           *XskUmem
	xsk            *XskSocket
	fill           XskRingProd
	comp           XskRingCons
	rx             XskRingCons
	tx             XskRingProd
	rxFreeDescList *list.List
	txFreeDescList *list.List
	umemArea       []byte
	config         SimpleXskConfig
	recvPktChan    chan []byte
	sendPktChan    chan []byte
	recvStopChan   chan struct{}
	sendStopChan   chan struct{}
}

func (simpleXsk *SimpleXsk) Fd() int {
	return simpleXsk.xsk.Fd
}

func (simpleXsk *SimpleXsk) populateFillRing() {
	pos := uint32(0)
	nb := XskRingProdReserve(&simpleXsk.fill, uint32(simpleXsk.rxFreeDescList.Len()), &pos)
	for i := uint32(0); i < nb; i++ {
		*XskRingProdFillAddr(&simpleXsk.fill, pos+i) = simpleXsk.rxFreeDescList.Remove(simpleXsk.rxFreeDescList.Front()).(uint64)
	}
	XskRingProdSubmit(&simpleXsk.fill, nb)
}

// 目前，pollTimeout 为 -1 时，存在无法关闭的风险
func (simpleXsk *SimpleXsk) StartRecv(chanBuffSize int32, pollTimeout int) <-chan []byte {
	if simpleXsk.recvPktChan != nil {
		return simpleXsk.recvPktChan
	}
	simpleXsk.recvPktChan = make(chan []byte, chanBuffSize)
	simpleXsk.recvStopChan = make(chan struct{})
	go func() {
		for {
			select {
			case <-simpleXsk.recvStopChan:
				close(simpleXsk.recvPktChan)
				return
			default:
				pos := uint32(0)
				nPkts := XskRingConsPeek(&simpleXsk.rx, uint32(simpleXsk.config.NumFrames/2), &pos)
				for i := uint32(0); i < nPkts; i++ {
					desc := XskRingConsRxDesc(&simpleXsk.rx, pos+i)
					pkt := make([]byte, desc.Len)
					copy(pkt, simpleXsk.umemArea[desc.Addr:desc.Addr+uint64(desc.Len)])
					simpleXsk.recvPktChan <- pkt
					simpleXsk.rxFreeDescList.PushBack(desc.Addr)
				}
				XskRingConsRelease(&simpleXsk.rx, nPkts)
				simpleXsk.populateFillRing()
				unix.Poll([]unix.PollFd{{
					Fd:     int32(simpleXsk.xsk.Fd),
					Events: unix.POLLIN,
				}}, pollTimeout)
			}
		}
	}()
	return simpleXsk.recvPktChan
}

func (simpleXsk *SimpleXsk) StopRecv() {
	if simpleXsk.recvStopChan != nil {
		simpleXsk.recvStopChan <- struct{}{}
		close(simpleXsk.recvStopChan)
		simpleXsk.recvStopChan = nil
	}
}

func (simpleXsk *SimpleXsk) recycleCompRing() {
	pos := uint32(0)
	nPkts := XskRingConsPeek(&simpleXsk.comp, uint32(simpleXsk.config.NumFrames/2), &pos)
	for i := uint32(0); i < nPkts; i++ {
		simpleXsk.txFreeDescList.PushBack(*XskRingConsCompAddr(&simpleXsk.comp, pos+i))
	}
	XskRingConsRelease(&simpleXsk.comp, nPkts)
}

func (simpleXsk *SimpleXsk) StartSend(chanBuffSize int32, pollTimeout int) chan<- []byte {
	if simpleXsk.sendPktChan != nil {
		return simpleXsk.sendPktChan
	}
	simpleXsk.sendPktChan = make(chan []byte, chanBuffSize)
	simpleXsk.sendStopChan = make(chan struct{})

	go func() {
		for {
			select {
			case <-simpleXsk.sendStopChan:
				close(simpleXsk.sendPktChan)
				return
			case pkt, ok := <-simpleXsk.sendPktChan:
				if !ok {
					return
				}
				for {
					simpleXsk.recycleCompRing()
					if simpleXsk.txFreeDescList.Len() > 0 {
						break
					}
				}
				pktNum := len(simpleXsk.sendPktChan) + 1 // 加上当前接收到的包
				// 此时，至少有一个
				if pktNum > simpleXsk.txFreeDescList.Len() {
					pktNum = simpleXsk.txFreeDescList.Len()
				}
				for {
					pos := uint32(0)
					nb := XskRingProdReserve(&simpleXsk.tx, uint32(pktNum), &pos)
					if nb == 0 {
						// 预留失败，回收空间并继续等待
						simpleXsk.recycleCompRing()
						continue
					}
					// 预留成功
					for i := uint32(0); i < nb; i++ {
						var currentPkt []byte
						if i == 0 {
							currentPkt = pkt
						} else {
							currentPkt = <-simpleXsk.sendPktChan
						}
						addr := simpleXsk.txFreeDescList.Remove(simpleXsk.txFreeDescList.Front()).(uint64)
						XskRingProdTxDesc(&simpleXsk.tx, pos+i).Addr = addr
						XskRingProdTxDesc(&simpleXsk.tx, pos+i).Len = uint32(len(currentPkt))
						copy(simpleXsk.umemArea[addr:addr+uint64(len(currentPkt))], currentPkt)
					}
					XskRingProdSubmit(&simpleXsk.tx, nb)
					unix.Poll([]unix.PollFd{{
						Fd:     int32(simpleXsk.xsk.Fd),
						Events: unix.POLLOUT,
					}}, pollTimeout)
					break
				}
			}
		}
	}()
	return simpleXsk.sendPktChan
}

func (simpleXsk *SimpleXsk) StopSend() {
	if simpleXsk.sendStopChan != nil {
		simpleXsk.sendStopChan <- struct{}{}
		close(simpleXsk.sendStopChan)
		simpleXsk.sendStopChan = nil
	}
}

func (simpleXsk *SimpleXsk) Close() {
	simpleXsk.StopRecv()
	simpleXsk.StopSend()
	if simpleXsk.xsk != nil {
		XskSocketDelete(simpleXsk.xsk)
		simpleXsk.xsk = nil
	}

	if simpleXsk.umem != nil {
		XskUmemDelete(simpleXsk.umem)
		simpleXsk.umem = nil
	}

	if simpleXsk.umemArea != nil {
		unix.Munmap(simpleXsk.umemArea)
		simpleXsk.umemArea = nil
	}
}

type SimpleXskConfig struct {
	NumFrames   int
	FrameSize   int
	LibbpfFlags uint32
}

func simpleXskSetConfig(cfg *SimpleXskConfig, usrCfg *SimpleXskConfig) error {
	if usrCfg == nil {
		cfg.NumFrames = 2048
		cfg.FrameSize = 4096
		cfg.LibbpfFlags = 0
		return nil
	}
	cfg.NumFrames = usrCfg.NumFrames
	cfg.FrameSize = usrCfg.FrameSize
	cfg.LibbpfFlags = usrCfg.LibbpfFlags
	return nil
}

func NewSimpleXsk(ifaceName string, queueID uint32, config *SimpleXskConfig) (*SimpleXsk, error) {
	simpleXsk := new(SimpleXsk)
	var err error
	simpleXskSetConfig(&simpleXsk.config, config)

	simpleXsk.umemArea, err = unix.Mmap(-1, 0, simpleXsk.config.NumFrames*simpleXsk.config.FrameSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE)
	if err != nil {
		return nil, err
	}

	simpleXsk.umem, err = XskUmemCreate(unsafe.Pointer(&simpleXsk.umemArea[0]),
		uint64(simpleXsk.config.NumFrames*simpleXsk.config.FrameSize),
		&simpleXsk.fill, &simpleXsk.comp,
		&XskUmemConfig{
			FillSize:      uint32(simpleXsk.config.NumFrames / 2),
			CompSize:      uint32(simpleXsk.config.NumFrames / 2),
			FrameSize:     uint32(simpleXsk.config.FrameSize),
			FrameHeadroom: uint32(0),
			Flags:         uint32(0),
		})
	if err != nil {
		goto outFreeUmemArea
	}

	simpleXsk.xsk, err = XskSocketCreate(ifaceName, uint32(queueID),
		simpleXsk.umem, &simpleXsk.rx, &simpleXsk.tx,
		&XskSocketConfig{
			RxSize:      uint32(simpleXsk.config.NumFrames / 2),
			TxSize:      uint32(simpleXsk.config.NumFrames / 2),
			XdpFlags:    link.XDPGenericMode,
			BindFlags:   unix.XDP_USE_NEED_WAKEUP,
			LibbpfFlags: simpleXsk.config.LibbpfFlags,
		})
	if err != nil {
		goto outFreeUmem
	}

	// 初始化
	simpleXsk.rxFreeDescList = list.New()
	simpleXsk.txFreeDescList = list.New()

	for i := uint32(0); i < uint32(simpleXsk.config.NumFrames/2); i++ {
		simpleXsk.txFreeDescList.PushBack(uint64(i * uint32(simpleXsk.config.FrameSize)))
	}

	for i := uint32(0); i < uint32(simpleXsk.config.NumFrames/2); i++ {
		simpleXsk.rxFreeDescList.PushBack(
			uint64((i + uint32(simpleXsk.config.NumFrames/2)) * uint32(simpleXsk.config.FrameSize)))
	}

	simpleXsk.recvPktChan = nil
	simpleXsk.sendPktChan = nil
	simpleXsk.recvStopChan = nil
	simpleXsk.sendStopChan = nil

	return simpleXsk, nil

outFreeUmem:
	XskUmemDelete(simpleXsk.umem)

outFreeUmemArea:
	unix.Munmap(simpleXsk.umemArea)
	return nil, err
}
