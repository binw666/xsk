package xsk

import (
	"container/list"
	"errors"
	"os"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type SimpleXsk struct {
	umem                 *XskUmem
	xsk                  *XskSocket
	fill                 XskRingProd
	comp                 XskRingCons
	rx                   XskRingCons
	tx                   XskRingProd
	rxFreeDescList       *list.List
	txFreeDescList       *list.List
	umemArea             []byte
	config               SimpleXskConfig
	recvPktChan          chan Packet
	sendPktChan          chan Packet
	stopRecvReadFd       int
	stopRecvWriteFd      int
	stopSendReadFd       int
	stopSendWriteFd      int
	recvStopFinishedChan chan struct{}
	sendStopNoticeChan   chan struct{}
	recvHandler          func([]byte)
}

// 多次 StartRecv 的错误
var ErrAnotherRecvRunning = errors.New("another recv goroutine is running")
var ErrAnotherRecvChanRunning = errors.New("another recv chan goroutine is running, params will not work")

// 多次 StartSend 的错误，参数不会生效
var ErrAnotherSendChanRunning = errors.New("another send chan goroutine is running, params will not work")

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

func (simpleXsk *SimpleXsk) StartRecv(chanBuffSize int32, pollTimeout int, recvHandler func([]byte)) error {
	if simpleXsk.recvHandler != nil {
		return ErrAnotherRecvRunning
	}
	simpleXsk.recvHandler = recvHandler
	simpleXsk.recvStopFinishedChan = make(chan struct{})

	// 创建管道用于停止信号
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	simpleXsk.stopRecvReadFd = int(r.Fd())
	simpleXsk.stopRecvWriteFd = int(w.Fd())

	go func() {
		defer r.Close()
		defer w.Close()
		defer close(simpleXsk.recvStopFinishedChan)
		for {
			pos := uint32(0)
			nPkts := XskRingConsPeek(&simpleXsk.rx, uint32(simpleXsk.config.NumFrames/2), &pos)
			for i := uint32(0); i < nPkts; i++ {
				desc := XskRingConsRxDesc(&simpleXsk.rx, pos+i)
				recvHandler(simpleXsk.umemArea[desc.Addr : desc.Addr+uint64(desc.Len)])
				simpleXsk.rxFreeDescList.PushBack(desc.Addr)
			}
			XskRingConsRelease(&simpleXsk.rx, nPkts)
			simpleXsk.populateFillRing()
			pollFds := []unix.PollFd{{
				Fd:     int32(simpleXsk.xsk.Fd),
				Events: unix.POLLIN,
			}, {
				Fd:     int32(simpleXsk.stopRecvReadFd),
				Events: unix.POLLIN,
			}}
			unix.Poll(pollFds, pollTimeout)
			if pollFds[1].Revents&unix.POLLIN != 0 {
				// 收到停止信号
				return
			}
		}
	}()
	return nil
}

// StartRecvChan 初始化并启动一个接收数据包的通道，具有指定的缓冲区大小和轮询超时。
// 它还允许使用一个可选的过滤函数来处理传入的数据包。
//
// 参数:
//   - chanBuffSize: 接收通道的缓冲区大小。
//   - pollTimeout: 轮询操作的超时时间。
//   - filter: 用于过滤传入数据包的函数。如果为 nil，则接受所有数据包。
//
// 返回值:
//   - (<-chan Packet): 一个只读通道，通过该通道接收数据包。
//   - (error): 如果另一个接收通道已经在运行或启动接收器时出现问题，则返回错误。
//
// 如果一个接收通道已经在运行，它将返回现有的通道，并返回一个错误，指示另一个接收通道已经在运行。
// 如果过滤函数为 nil，则使用一个接受所有数据包的默认过滤器。
func (simpleXsk *SimpleXsk) StartRecvChan(chanBuffSize int32, pollTimeout int, filter func([]byte) bool) (<-chan Packet, error) {
	if simpleXsk.recvPktChan != nil {
		return simpleXsk.recvPktChan, ErrAnotherRecvChanRunning
	}
	if filter == nil {
		filter = func([]byte) bool { return true }
	}
	simpleXsk.recvPktChan = make(chan Packet, chanBuffSize)
	recvHandler := func(desc []byte) {
		if !filter(desc) {
			return
		}
		pkt := new(SimplePacket)
		pkt.SetData(desc)
		simpleXsk.recvPktChan <- pkt
	}
	err := simpleXsk.StartRecv(chanBuffSize, pollTimeout, recvHandler)
	if err != nil {
		close(simpleXsk.recvPktChan)
		return nil, err
	}
	return simpleXsk.recvPktChan, nil
}

// StopRecv 停止接收数据包，用来关闭 StartRecvChan 或 StartRecv 。
func (simpleXsk *SimpleXsk) StopRecv() {
	if simpleXsk.recvHandler != nil {
		unix.Write(simpleXsk.stopRecvWriteFd, []byte{1})
		<-simpleXsk.recvStopFinishedChan
		simpleXsk.recvStopFinishedChan = nil
		simpleXsk.recvHandler = nil
		if simpleXsk.recvPktChan != nil {
			close(simpleXsk.recvPktChan)
			simpleXsk.recvPktChan = nil
		}
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

// StartSendChan 初始化并启动一个发送数据包的通道。
// 它创建一个用于数据包的缓冲通道和一个停止通知通道。
// 它还设置了一个用于处理停止信号的管道，并启动一个 goroutine 来处理发送通道中的数据包。
//
// 参数:
// - chanBuffSize: 数据包缓冲通道的大小。
// - pollTimeout: 轮询操作的超时时间。
// - postProcess: 一个用于后处理每个数据包的函数。
//
// 返回值:
// - chan<- Packet: 一个用于发送数据包的发送通道。
// - error: 如果另一个发送通道已经在运行，则返回错误。
//
// 如果一个发送通道已经在运行，它将返回现有的通道，并返回一个错误，指示另一个发送通道已经在运行。
// 如果发送通道被外部关闭，goroutine 将清理资源并退出。
func (simpleXsk *SimpleXsk) StartSendChan(chanBuffSize int32, pollTimeout int, postProcess func(Packet)) (chan<- Packet, error) {
	if simpleXsk.sendPktChan != nil {
		return simpleXsk.sendPktChan, ErrAnotherSendChanRunning
	}
	simpleXsk.sendPktChan = make(chan Packet, chanBuffSize)
	simpleXsk.sendStopNoticeChan = make(chan struct{})

	// 创建管道用于停止信号
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	simpleXsk.stopSendReadFd = int(r.Fd())
	simpleXsk.stopSendWriteFd = int(w.Fd())

	go func() {
		defer r.Close()
		defer w.Close()
		defer close(simpleXsk.sendPktChan)
		for {
			select {
			case <-simpleXsk.sendStopNoticeChan:
				return
			case pkt, ok := <-simpleXsk.sendPktChan:
				if !ok {
					// 被外界关闭
					simpleXsk.sendPktChan = nil
					close(simpleXsk.sendStopNoticeChan)
					simpleXsk.sendStopNoticeChan = nil
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
						pollFds := []unix.PollFd{{
							Fd:     int32(simpleXsk.xsk.Fd),
							Events: unix.POLLOUT,
						}, {
							Fd:     int32(simpleXsk.stopSendReadFd),
							Events: unix.POLLIN,
						}}
						unix.Poll(pollFds, pollTimeout)
						if pollFds[1].Revents&unix.POLLIN != 0 {
							// 收到停止信号
							<-simpleXsk.sendStopNoticeChan
							return
						}
						continue
					}
					// 预留成功
					for i := uint32(0); i < nb; i++ {
						var currentPkt Packet
						if i == 0 {
							currentPkt = pkt
						} else {
							currentPkt = <-simpleXsk.sendPktChan
						}
						addr := simpleXsk.txFreeDescList.Remove(simpleXsk.txFreeDescList.Front()).(uint64)
						XskRingProdTxDesc(&simpleXsk.tx, pos+i).Addr = addr
						XskRingProdTxDesc(&simpleXsk.tx, pos+i).Len = uint32(currentPkt.Len())
						copy(simpleXsk.umemArea[addr:addr+uint64(currentPkt.Len())], currentPkt.Data())
						if postProcess != nil {
							postProcess(currentPkt)
						}
					}
					XskRingProdSubmit(&simpleXsk.tx, nb)
					pollFds := []unix.PollFd{{
						Fd:     int32(simpleXsk.xsk.Fd),
						Events: unix.POLLOUT,
					}, {
						Fd:     int32(simpleXsk.stopSendReadFd),
						Events: unix.POLLIN,
					}}
					unix.Poll(pollFds, pollTimeout)
					if pollFds[1].Revents&unix.POLLIN != 0 {
						// 收到停止信号
						<-simpleXsk.sendStopNoticeChan
						return
					}
					break
				}
			}
		}
	}()
	return simpleXsk.sendPktChan, nil
}

func (simpleXsk *SimpleXsk) StopSendChan() {
	if simpleXsk.sendStopNoticeChan != nil {
		unix.Write(simpleXsk.stopSendWriteFd, []byte{1})
		simpleXsk.sendStopNoticeChan <- struct{}{}
		close(simpleXsk.sendStopNoticeChan)
		simpleXsk.sendStopNoticeChan = nil
	}
}

func (simpleXsk *SimpleXsk) Close() {
	simpleXsk.StopRecv()
	simpleXsk.StopSendChan()
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
	simpleXsk.recvStopFinishedChan = nil
	simpleXsk.sendStopNoticeChan = nil
	simpleXsk.stopRecvReadFd = -1
	simpleXsk.stopRecvWriteFd = -1
	simpleXsk.stopSendReadFd = -1
	simpleXsk.stopSendWriteFd = -1

	return simpleXsk, nil

outFreeUmem:
	XskUmemDelete(simpleXsk.umem)

outFreeUmemArea:
	unix.Munmap(simpleXsk.umemArea)
	return nil, err
}
