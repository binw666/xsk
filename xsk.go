package xsk

import (
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// XskSocketCreate 创建一个 XskSocket，用于指定的网络接口和队列 ID。
// 它需要一个有效的 XskUmem、用于 RX 的 XskRingCons、用于 TX 的 XskRingProd 和一个可选的 XskSocketConfig。
// 如果提供的 umem 为 nil，则返回错误 (unix.EFAULT)。
// 该函数内部调用 xskSocketCreateShared，传递存储在 umem 中的填充环和完成环。
//
// 参数:
// - ifname: 网络接口的名称。
// - queueId: 要关联的队列 ID。
// - umem: 指向 XskUmem 结构的指针。
// - rx: 指向 RX 的 XskRingCons 结构的指针。
// - tx: 指向 TX 的 XskRingProd 结构的指针。
// - usrConfig: 指向 XskSocketConfig 结构的指针（可选，或为 nil）。
//
// 返回值:
// - 指向创建的 XskSocket 的指针。
// - 如果 umem 为 nil 或套接字创建失败，则返回错误。
func XskSocketCreate(ifname string, queueId uint32, umem *XskUmem, rx *XskRingCons, tx *XskRingProd, usrConfig *XskSocketConfig) (*XskSocket, error) {
	if umem == nil {
		return nil, unix.EFAULT
	}
	// xsk_socket__create_shared 需要多传 fill ring 和 rx ring，这里将暂存在 umem 中的 fill ring 和 rx ring 传入
	return XskSocketCreateShared(ifname, queueId, umem, rx, tx, umem.FillSave, umem.CompSave, usrConfig)
}

// XskSocketCreateShared 创建一个共享的 XDP 套接字，用于指定的网络接口和队列 ID。
// 它使用提供的 UMEM、RX、TX、填充和完成环设置套接字，并应用用户配置。
//
// 参数:
// - ifname: 网络接口的名称。
// - queueId: 要使用的队列 ID。
// - umem: 指向 XskUmem 结构的指针。
// - rx: 指向 RX 环的 XskRingCons 结构的指针。
// - tx: 指向 TX 环的 XskRingProd 结构的指针。
// - fill: 指向填充环的 XskRingProd 结构的指针。
// - comp: 指向完成环的 XskRingCons 结构的指针。
// - usrConfig: 指向用户配置的 XskSocketConfig 结构的指针。
//
// 返回值:
// - 指向创建的 XskSocket 结构的指针。
// - 如果套接字创建或设置失败，则返回错误。
//
// 该函数执行以下步骤：
// 1. 验证输入参数。
// 2. 将用户配置复制到套接字配置中，如果 usrConfig 为 NULL，则加载默认参数。
// 3. 按名称检索网络接口。
// 4. 增加 UMEM 引用计数，如果引用计数大于 1，则创建一个新的套接字。
// 5. 检索指定 netns、接口索引和队列 ID 的上下文，如果没有则创建一个（fill 和 comp 会被重新设置）。
// 6. 如果提供了 RX 和 TX 环且尚未设置，则设置它们。
// 7. 将 RX 和 TX 环映射到用户空间。
// 8. 将套接字绑定到指定的接口和队列 ID。
// 9. 如果用户配置未禁止，则加载默认的 XDP 程序。
// 10. 返回创建的套接字，如果任何步骤失败，则返回错误。
func XskSocketCreateShared(ifname string, queueId uint32, umem *XskUmem, rx *XskRingCons, tx *XskRingProd, fill *XskRingProd, comp *XskRingCons, usrConfig *XskSocketConfig) (*XskSocket, error) {
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
		// 如果引用次数大于 1，说明初始化 umem 时创建的套接字已经被使用了，这里创建一个新的套接字
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
	// 获取 netns_cookie，如果获取失败，则 netns_cookie = INIT_NS
	netnsCookie, err = unix.GetsockoptUint64(xsk.Fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil {
		if err != unix.ENOPROTOOPT {
			goto outSocket
		}
		// 错误为 ENOPROTOOPT 说明内核不支持这个选项，直接赋值为 INIT_NS
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
		// CachedCons 比 Consumer 大 r->size
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

// xskSetXdpSocketConfig 根据用户提供的设置配置 XskSocketConfig 结构。
// 如果用户配置为 nil，则设置默认值。
// 如果提供了用户配置，则验证 LibbpfFlags 并从用户配置中复制值。
//
// 参数:
// - cfg: 指向要配置的 XskSocketConfig 结构的指针。
// - usrCfg: 指向用户提供的 XskSocketConfig 结构的指针。如果为 nil，则使用默认值。
//
// 返回值:
// - error: 如果用户提供的 LibbpfFlags 包含无效标志，则返回错误，否则返回 nil。
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

// xskGetCtx 从提供的 XskUmem 的上下文列表中检索与指定的网络命名空间 cookie、接口索引和队列 ID 匹配的 XskCtx。
// 如果找到匹配的上下文，则其引用计数递增并返回该上下文。如果没有找到匹配的上下文，则函数返回 nil。
//
// 参数:
//   - umem: 指向包含上下文列表的 XskUmem 的指针。
//   - netnsCookie: 要匹配的网络命名空间 cookie。
//   - ifindex: 要匹配的接口索引。
//   - queueId: 要匹配的队列 ID。
//
// 返回值:
//   - 如果找到匹配的 XskCtx，则返回指向该 XskCtx 的指针，否则返回 nil。
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

// xskCreateCtx 创建一个新的 XskCtx 上下文。
//
// 参数：
// - xsk: 指向 XskSocket 的指针。
// - umem: 指向 XskUmem 的指针。
// - netnsCookie: 网络命名空间的 cookie。
// - ifindex: 网络接口的索引。
// - ifname: 网络接口的名称。
// - queueId: 队列 ID。
// - fill: 指向 XskRingProd 的指针，用于填充环。
// - comp: 指向 XskRingCons 的指针，用于完成环。
//
// 返回值：
// - *XskCtx: 指向新创建的 XskCtx 的指针。
// - error: 如果创建过程中出现错误，则返回错误信息。
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

// xskPutCtx 释放与 XskCtx 实例关联的资源。
// 它会递减上下文的引用计数，如果引用计数达到零，它会选择性地取消映射与填充环和完成环相关的内存区域。
//
// 参数:
// - ctx: 指向要释放的 XskCtx 实例的指针。
// - ummap: 一个布尔标志，指示是否取消映射内存区域。
//
// 该函数执行以下步骤：
// 1. 递减上下文的引用计数。
// 2. 如果引用计数不为零，函数立即返回。
// 3. 如果 ummap 标志为 false，函数从列表中移除上下文并返回。
// 4. 如果 ummap 标志为 true，函数检索内存映射偏移量并取消映射填充环和完成环。
// 5. 最后，函数从 umem 结构的上下文列表中移除上下文。
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
		if ctxValue, ok := e.Value.(*XskCtx); ok && ctxValue == ctx {
			umem.CtxList.Remove(e)
			return // 删除第一个匹配的元素后返回
		}
	}
}

// XskSocketDelete 删除一个 XskSocket 实例并释放相关资源。
//
// 参数:
//   - xsk: 指向要删除的 XskSocket 实例的指针。如果 xsk 为 nil，函数立即返回。
//
// 该函数执行以下操作:
//  1. 检查提供的 XskSocket 实例 (xsk) 是否为 nil。如果是，函数立即返回。
//  2. 检索与 XskSocket 实例关联的上下文 (ctx) 和 umem。
//  3. 如果上下文中附加了 XDP 程序，则从 XsksMap 中删除 XDP 程序，关闭 XsksMap，并释放 XDP 程序。
//  4. 检索 XskSocket 文件描述符 (Fd) 的内存映射偏移量。如果成功，则在 Rx 和 Tx 环不为 nil 的情况下取消映射它们。
//  5. 释放与 XskSocket 实例关联的上下文。
//  6. 减少 umem 的引用计数。
//  7. 如果 XskSocket 实例的文件描述符 (Fd) 与 umem 的文件描述符不同，则关闭它。
func XskSocketDelete(xsk *XskSocket) {
	if xsk == nil {
		return
	}

	ctx := xsk.Ctx
	umem := ctx.Umem
	if ctx.XdpProg != nil {
		ctx.XsksMap.Delete(&ctx.QueueId)
		ctx.XsksMap.Close()
		ctx.XsksMap = nil
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
	// 不要关闭与 umem 关联的 fd
	if xsk.Fd != umem.Fd {
		unix.Close(xsk.Fd)
	}
}
