package xsk

import (
	"unsafe"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type XDPDesc = unix.XDPDesc

type ComplexXsk struct {
	xsk      *XskSocket
	umemArea []byte
	umem     *XskUmem
	config   ComplexXskConfig
	fill     XskRingProd
	comp     XskRingCons
	rx       XskRingCons
	tx       XskRingProd
}

type ComplexUmemConfig struct {
	FillSize      uint32
	CompSize      uint32
	FrameNum      uint32
	FrameSize     uint32
	FrameHeadroom uint32
	Flags         uint32
}
type ComplexSocketConfig struct {
	RxSize      uint32
	TxSize      uint32
	LibbpfFlags uint32
	XdpFlags    link.XDPAttachFlags
	BindFlags   uint16
}

type ComplexXskConfig struct {
	UmemConfig   *ComplexUmemConfig
	SocketConfig *ComplexSocketConfig
}

func DefaultComplexUmemConfig() *ComplexUmemConfig {
	return &ComplexUmemConfig{
		FillSize:      2048,
		CompSize:      2048,
		FrameNum:      4096,
		FrameSize:     2048,
		FrameHeadroom: 0,
		Flags:         0,
	}
}

func DefaultComplexSocketConfig() *ComplexSocketConfig {
	return &ComplexSocketConfig{
		RxSize:      2048,
		TxSize:      2048,
		LibbpfFlags: 0,
		XdpFlags:    link.XDPGenericMode,
		BindFlags:   unix.XDP_USE_NEED_WAKEUP,
	}
}

func DefaultComplexXskConfig() *ComplexXskConfig {
	return &ComplexXskConfig{
		UmemConfig:   DefaultComplexUmemConfig(),
		SocketConfig: DefaultComplexSocketConfig(),
	}
}

func NewComplexXsk(ifaceName string, queueID uint32, config *ComplexXskConfig) (*ComplexXsk, []XDPDesc, error) {
	complexXsk := new(ComplexXsk)
	var err error
	var descs []XDPDesc
	if config == nil {
		complexXsk.config = *DefaultComplexXskConfig()
	} else {
		complexXsk.config = *config
		if complexXsk.config.UmemConfig == nil {
			complexXsk.config.UmemConfig = DefaultComplexUmemConfig()
		}
		if complexXsk.config.SocketConfig == nil {
			complexXsk.config.SocketConfig = DefaultComplexSocketConfig()
		}
	}

	complexXsk.umemArea, err = unix.Mmap(-1, 0, int(complexXsk.config.UmemConfig.FrameNum)*int(complexXsk.config.UmemConfig.FrameSize),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE)
	if err != nil {
		return nil, nil, err
	}

	complexXsk.umem, err = XskUmemCreate(unsafe.Pointer(&complexXsk.umemArea[0]),
		uint64(complexXsk.config.UmemConfig.FrameNum*complexXsk.config.UmemConfig.FrameSize),
		&complexXsk.fill, &complexXsk.comp,
		&XskUmemConfig{
			FillSize:      complexXsk.config.UmemConfig.FillSize,
			CompSize:      complexXsk.config.UmemConfig.CompSize,
			FrameSize:     complexXsk.config.UmemConfig.FrameSize,
			FrameHeadroom: uint32(0),
			Flags:         uint32(0),
		})
	if err != nil {
		goto outFreeUmemArea
	}

	complexXsk.xsk, err = XskSocketCreate(ifaceName, uint32(queueID),
		complexXsk.umem, &complexXsk.rx, &complexXsk.tx,
		&XskSocketConfig{
			RxSize:      complexXsk.config.SocketConfig.RxSize,
			TxSize:      complexXsk.config.SocketConfig.TxSize,
			XdpFlags:    complexXsk.config.SocketConfig.XdpFlags,
			BindFlags:   complexXsk.config.SocketConfig.BindFlags,
			LibbpfFlags: complexXsk.config.SocketConfig.LibbpfFlags,
		})
	if err != nil {
		goto outFreeUmem
	}
	descs = make([]XDPDesc, complexXsk.config.UmemConfig.FrameNum)
	for i := uint32(0); i < complexXsk.config.UmemConfig.FrameNum; i++ {
		descs[i].Addr = uint64(i * complexXsk.config.UmemConfig.FrameSize)
	}

	return complexXsk, descs, nil

outFreeUmem:
	XskUmemDelete(complexXsk.umem)

outFreeUmemArea:
	unix.Munmap(complexXsk.umemArea)
	return nil, nil, err
}

func (xsk *ComplexXsk) PopulateFillRing(descs []XDPDesc) []XDPDesc {
	pos := uint32(0)
	freeSize := XskProdNbFree(&xsk.fill, uint32(len(descs)))
	if freeSize > uint32(len(descs)) {
		freeSize = uint32(len(descs))
	}
	nb := XskRingProdReserve(&xsk.fill, freeSize, &pos)
	for i := uint32(0); i < nb; i++ {
		*XskRingProdFillAddr(&xsk.fill, pos+i) = descs[i].Addr
	}
	XskRingProdSubmit(&xsk.fill, nb)
	leftDescs := make([]XDPDesc, len(descs)-int(nb))
	copy(leftDescs, descs[nb:])
	return leftDescs
}

func (xsk *ComplexXsk) RecycleRxRing() []XDPDesc {
	pos := uint32(0)
	nPkts := XskRingConsPeek(&xsk.rx, xsk.config.SocketConfig.RxSize, &pos)
	descs := make([]XDPDesc, nPkts)
	for i := uint32(0); i < nPkts; i++ {
		desc := XskRingConsRxDesc(&xsk.rx, pos+i)
		descs[i] = *desc
	}
	XskRingConsRelease(&xsk.rx, nPkts)
	return descs
}

func (xsk *ComplexXsk) PopulateTxRing(descs []XDPDesc) []XDPDesc {
	pos := uint32(0)
	freeSize := XskProdNbFree(&xsk.tx, uint32(len(descs)))
	if freeSize > uint32(len(descs)) {
		freeSize = uint32(len(descs))
	}
	nb := XskRingProdReserve(&xsk.tx, freeSize, &pos)
	for i := uint32(0); i < nb; i++ {
		XskRingProdTxDesc(&xsk.tx, pos+i).Addr = descs[i].Addr
		XskRingProdTxDesc(&xsk.tx, pos+i).Len = descs[i].Len
	}
	XskRingProdSubmit(&xsk.tx, nb)
	leftDescs := make([]XDPDesc, len(descs)-int(nb))
	copy(leftDescs, descs[nb:])
	return leftDescs
}

func (xsk *ComplexXsk) RecycleCompRing() []XDPDesc {
	pos := uint32(0)
	nPkts := XskRingConsPeek(&xsk.comp, xsk.umem.Config.CompSize, &pos)
	descs := make([]XDPDesc, nPkts)
	for i := uint32(0); i < nPkts; i++ {
		descs[i].Addr = *XskRingConsCompAddr(&xsk.comp, pos+i)
	}
	XskRingConsRelease(&xsk.comp, nPkts)
	return descs
}

func (xsk *ComplexXsk) Close() {
	if xsk.xsk != nil {
		XskSocketDelete(xsk.xsk)
		xsk.xsk = nil
	}

	if xsk.umem != nil {
		XskUmemDelete(xsk.umem)
		xsk.umem = nil
	}

	if xsk.umemArea != nil {
		unix.Munmap(xsk.umemArea)
		xsk.umemArea = nil
	}
}

func (xsk *ComplexXsk) Poll(events int16, timeout int) int16 {
	pollFds := []unix.PollFd{
		{
			Fd:     int32(xsk.xsk.Fd),
			Events: events,
		},
	}
	unix.Poll(pollFds, timeout)
	return pollFds[0].Revents
}

func (xsk *ComplexXsk) UmemArea(desc XDPDesc) []byte {
	return xsk.umemArea[desc.Addr : desc.Addr+uint64(xsk.config.UmemConfig.FrameSize)]
}
