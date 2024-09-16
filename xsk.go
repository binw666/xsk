package xsk

import (
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

func XskSocketCreate(ifname string, queueId uint32, umem *XskUmem, rx *XskRingCons, tx *XskRingProd, usrConfig *XskSocketConfig) (*XskSocket, error) {
	if umem == nil {
		return nil, unix.EFAULT
	}
	// xsk_socket__create_shared 需要多传 fill ring 和 rx ring，这里将暂存在 umem 中的 fill ring 和 rx ring 传入
	return xskSocketCreateShared(ifname, queueId, umem, rx, tx, umem.FillSave, umem.CompSave, usrConfig)
}

func xskSocketCreateShared(ifname string, queueId uint32, umem *XskUmem, rx *XskRingCons, tx *XskRingProd, fill *XskRingProd, comp *XskRingCons, usrConfig *XskSocketConfig) (*XskSocket, error) {
	var (
		rxSetupDone, txSetupDone bool
		rxMap, txMap             []byte
		sxdp                     unix.SockaddrXDP
		off                      unix.XDPMmapOffsets
		xsk                      *XskSocket
		ctx                      *XskCtx
		netnsCookie              uint64
		err                      error
		iface                    *net.Interface
		unmap                    bool
	)

	if umem == nil || (rx == nil && tx == nil) {
		return nil, unix.EFAULT
	}

	xsk = new(XskSocket)
	// 将 usr_config 拷贝到 xsk->config，如果为 NULL，则载入默认参数。此外，还进行参数检查。
	err = xskSetXdpSocketConfig(&xsk.Config, usrConfig)
	if err != nil {
		return nil, err
	}

	iface, err = net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	// 刚刚创建的 umem 的 umem->refcount = 0
	if umem.Refcount++; umem.Refcount > 1 {
		xsk.Fd, err = unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
		if err != nil {
			return nil, err
		}
	} else {
		// 如果引用次数为 0，会使用 umem 中已经创建了的套接字 fd
		xsk.Fd = umem.Fd
		rxSetupDone = umem.RxRingSetupDone
		txSetupDone = umem.TxRingSetupDone
	}
	netnsCookie, err = unix.GetsockoptUint64(xsk.Fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil {
		if err != unix.ENOPROTOOPT {
			goto outSocket
		}
		netnsCookie = INIT_NS
	}
	// 获取ctx，一个ctx对应一个 netns_cookie、ifindex、queue_id 的组合，每一种这样的组合都需要一对 fill 和 comp ring
	// 如果获取到了，则 ctx 引用 +1
	ctx = xskGetCtx(umem, netnsCookie, iface.Index, queueId)
	if ctx == nil {
		// 获取失败，并且 fill 和 comp 都为 NULL，无法存放后续创建的 fill 和 comp
		if fill == nil || comp == nil {
			err = unix.EFAULT
			goto outSocket
		}
		// 创建 ctx
		ctx, err = xskCreateCtx(xsk, umem, netnsCookie, iface.Index, iface.Name, queueId, fill, comp)
		if err != nil {
			goto outSocket
		}
	}
	xsk.Ctx = ctx
	// rx 不为 NUll 并且 rx_setup_done 为 false（如果是新创建的则肯定为false，如果是使用umem中的，则看umem->rx_ring_setup_done）
	if rx != nil && !rxSetupDone {
		// 设置 rx ring 大小
		err = unix.SetsockoptInt(xsk.Fd, unix.SOL_XDP, unix.XDP_RX_RING, int(xsk.Config.RxSize))
		if err != nil {
			goto outPutCtx
		}
		if xsk.Fd == umem.Fd {
			umem.RxRingSetupDone = true
		}
	}
	// tx 不为 NUll 并且 tx_setup_done 为 false（如果是新创建的则肯定为false，如果是使用umem中的，则看umem->tx_ring_setup_done）
	if tx != nil && !txSetupDone {
		// 设置 tx ring 大小
		err = unix.SetsockoptInt(xsk.Fd, unix.SOL_XDP, unix.XDP_TX_RING, int(xsk.Config.TxSize))
		if err != nil {
			goto outPutCtx
		}
		// 如果是使用 umem 中的，则 umem->tx_ring_setup_done = true
		if xsk.Fd == umem.Fd {
			umem.TxRingSetupDone = true
		}
	}
	// 获取偏移量，用户后面用户态维护的 rx ring 和 tx ring 的映射
	off, err = xskGetMmapOffsets(xsk.Fd)
	if err != nil {
		goto outPutCtx
	}
	// 如果 rx 不为 NULL，则设置 rx，并做映射
	if rx != nil {
		rxMap, err = unix.Mmap(xsk.Fd, unix.XDP_PGOFF_RX_RING,
			int(off.Rx.Desc+uint64(xsk.Config.RxSize)*uint64(unsafe.Sizeof(unix.XDPDesc{}))),
			unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
		if err != nil {
			goto outPutCtx
		}
		rx.Mask = xsk.Config.RxSize - 1
		rx.Size = xsk.Config.RxSize
		rx.Producer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&rxMap[0])) + uintptr(off.Rx.Producer)))
		rx.Consumer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&rxMap[0])) + uintptr(off.Rx.Consumer)))
		rx.Flags = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&rxMap[0])) + uintptr(off.Rx.Flags)))
		rx.Ring = unsafe.Pointer(uintptr(unsafe.Pointer(&rxMap[0])) + uintptr(off.Rx.Desc))
		rx.CachedProd = *rx.Producer
		rx.CachedCons = *rx.Consumer
	}
	xsk.Rx = rx
	// 如果 tx 不为 NULL，则设置 tx，并做映射
	if tx != nil {
		txMap, err = unix.Mmap(xsk.Fd, unix.XDP_PGOFF_TX_RING,
			int(off.Tx.Desc+uint64(xsk.Config.TxSize)*uint64(unsafe.Sizeof(unix.XDPDesc{}))),
			unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
		if err != nil {
			goto outMmapRx
		}
		tx.Mask = xsk.Config.TxSize - 1
		tx.Size = xsk.Config.TxSize
		tx.Producer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&txMap[0])) + uintptr(off.Tx.Producer)))
		tx.Consumer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&txMap[0])) + uintptr(off.Tx.Consumer)))
		tx.Flags = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&txMap[0])) + uintptr(off.Tx.Flags)))
		tx.Ring = unsafe.Pointer(uintptr(unsafe.Pointer(&txMap[0])) + uintptr(off.Tx.Desc))
		tx.CachedProd = *tx.Producer
		// CachedCons 比 Consumer 大 r->size（源码这么写的，我觉得应该是 TxSize）
		tx.CachedCons = *tx.Consumer + xsk.Config.TxSize
	}
	xsk.Tx = tx

	// 准备 bind
	sxdp.Ifindex = uint32(ctx.Ifindex)
	sxdp.QueueID = ctx.QueueId
	if umem.Refcount > 1 {
		sxdp.Flags |= unix.XDP_SHARED_UMEM
		sxdp.SharedUmemFD = uint32(umem.Fd)
	} else {
		sxdp.Flags = xsk.Config.BindFlags
	}
	// 这里的 bind 可以理解成绑定之前设置的umem（或共享的）、fill、comp到套接字（最开始设置时fill和comp只是暂存，实际内核在这个阶段创建了pool）
	err = unix.Bind(xsk.Fd, &sxdp)
	if err != nil {
		goto outMmapTx
	}
	// 如果不禁止 prog 加载，则自动载入默认xdp程序
	if xsk.Config.LibbpfFlags&XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD == 0 {
		err = xskSetupXdpProg(xsk, nil)
		if err != nil {
			goto outMmapTx
		}
	}
	// 暂存的 fill 和 comp 已被使用，如果还想要，那就本函数创建 ctx 吧（如果没有适合的 ctx 的话）
	umem.FillSave = nil
	umem.CompSave = nil
	return xsk, nil

outMmapTx:
	if tx != nil {
		unix.Munmap(txMap)
	}

outMmapRx:
	if rx != nil {
		unix.Munmap(rxMap)
	}

outPutCtx:
	unmap = umem.FillSave != fill
	xskPutCtx(ctx, unmap)

outSocket:
	// 保留 umem 所依附的那个 fd，其他的多余的都关闭
	if umem.Refcount--; umem.Refcount != 0 {
		unix.Close(xsk.Fd)
	}
	return nil, err
}

func xskSetXdpSocketConfig(cfg *XskSocketConfig, usrCfg *XskSocketConfig) error {
	if usrCfg == nil {
		cfg.RxSize = XSK_RING_CONS__DEFAULT_NUM_DESCS
		cfg.TxSize = XSK_RING_PROD__DEFAULT_NUM_DESCS
		cfg.LibbpfFlags = 0
		cfg.XdpFlags = 0
		cfg.BindFlags = 0
		return nil
	}
	if usrCfg.LibbpfFlags & ^XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD != 0 {
		return unix.EINVAL
	}
	cfg.RxSize = usrCfg.RxSize
	cfg.TxSize = usrCfg.TxSize
	cfg.LibbpfFlags = usrCfg.LibbpfFlags
	cfg.XdpFlags = usrCfg.XdpFlags
	cfg.BindFlags = usrCfg.BindFlags

	return nil
}

func xskGetCtx(umem *XskUmem, netnsCookie uint64, ifindex int, queueId uint32) *XskCtx {
	for node := umem.CtxList.Front(); node != nil; node = node.Next() {
		ctx := node.Value.(*XskCtx)
		if ctx.NetnsCookie == netnsCookie && ctx.Ifindex == ifindex && ctx.QueueId == queueId {
			ctx.Refcount++
			return ctx
		}
	}
	return nil
}

func xskCreateCtx(xsk *XskSocket, umem *XskUmem, netnsCookie uint64, ifindex int, ifname string, queueId uint32, fill *XskRingProd, comp *XskRingCons) (*XskCtx, error) {
	var ctx *XskCtx = new(XskCtx)
	var err error
	// 检查暂存的 fill 和 comp 是否被用掉了
	if umem.FillSave == nil {
		// 被用掉了，创建新的 fill 和 comp
		err = xskCreateUmemRings(umem, xsk.Fd, fill, comp)
		if err != nil {
			return nil, err
		}
	} else if umem.FillSave != fill || umem.CompSave != comp {
		*fill = *umem.FillSave
		*comp = *umem.CompSave
	}
	ctx.NetnsCookie = netnsCookie
	ctx.Ifindex = ifindex
	ctx.Refcount = 1
	ctx.Umem = umem
	ctx.QueueId = queueId
	ctx.Ifname = ifname
	ctx.Fill = fill
	ctx.Comp = comp
	umem.CtxList.PushBack(ctx)
	return ctx, nil
}

func xskPutCtx(ctx *XskCtx, ummap bool) {
	var umem = ctx.Umem
	var off unix.XDPMmapOffsets
	var err error
	var fillMapPtr uintptr
	var fillMapLen int
	var fillMap []byte
	var compMapPtr uintptr
	var compMapLen int
	var compMap []byte

	// 还有人在用
	if ctx.Refcount--; ctx.Refcount != 0 {
		return
	}
	// 其中 unmap = umem.FillSave != fill
	// 如果 ummap = false，则说明 umem.FillSave == fill，只需要从列表中移除 ctx
	if !ummap {
		goto outFree
	}
	// 这里应该是用哪个套接字都可以，毕竟布局相同
	off, err = xskGetMmapOffsets(umem.Fd)
	if err != nil {
		goto outFree
	}
	// 解除 fill 和 comp 的映射
	fillMapPtr = uintptr(ctx.Fill.Ring) - uintptr(off.Fr.Desc)
	fillMapLen = int(off.Fr.Desc + uint64(umem.Config.FillSize)*uint64(unsafe.Sizeof(uint64(0))))
	fillMap = unsafe.Slice((*byte)(unsafe.Pointer(fillMapPtr)), fillMapLen)
	unix.Munmap(fillMap)

	compMapPtr = uintptr(ctx.Comp.Ring) - uintptr(off.Cr.Desc)
	compMapLen = int(off.Cr.Desc + uint64(umem.Config.CompSize)*uint64(unsafe.Sizeof(uint64(0))))
	compMap = unsafe.Slice((*byte)(unsafe.Pointer(compMapPtr)), compMapLen)
	unix.Munmap(compMap)
outFree:
	for e := umem.CtxList.Front(); e != nil; e = e.Next() {
		if e.Value.(*XskCtx) == ctx {
			umem.CtxList.Remove(e)
			return // 删除第一个匹配的元素后返回
		}
	}
}

func XskInitXskStruct(xsk *XskSocket, ifindex int) error {
	ctx := new(XskCtx)
	iface, err := net.InterfaceByIndex(ifindex)
	if err != nil {
		return err
	}
	ctx.Ifindex = ifindex
	ctx.Ifname = iface.Name
	xsk.Ctx = ctx
	return nil
}

func xskDestroyXskStruct(xsk *XskSocket) {
	xsk.Ctx.XdpProg.Close()
}

// 对应函数 xsk_socket__delete
func XskSocketDelete(xsk *XskSocket) {
	if xsk == nil {
		return
	}

	ctx := xsk.Ctx
	umem := ctx.Umem
	if ctx.XdpProg != nil {
		xskDeleteMapEntry(ctx.XsksMap, ctx.QueueId)
		xskReleaseXdpProg(xsk)
	}

	off, err := xskGetMmapOffsets(xsk.Fd)
	if err == nil {
		if xsk.Rx != nil {
			unix.Munmap(unsafe.Slice((*byte)(unsafe.Pointer(uintptr(xsk.Rx.Ring)-uintptr(off.Rx.Desc))),
				int(off.Rx.Desc+uint64(xsk.Config.RxSize)*uint64(unsafe.Sizeof(unix.XDPDesc{})))))
		}
		if xsk.Tx != nil {
			unix.Munmap(unsafe.Slice((*byte)(unsafe.Pointer(uintptr(xsk.Tx.Ring)-uintptr(off.Tx.Desc))),
				int(off.Tx.Desc+uint64(xsk.Config.TxSize)*uint64(unsafe.Sizeof(unix.XDPDesc{})))))
		}
	}

	xskPutCtx(ctx, true)

	umem.Refcount--
	// 不要关闭一个文件描述符，如果它还连接有关联的umem
	if xsk.Fd != umem.Fd {
		unix.Close(xsk.Fd)
	}
}
