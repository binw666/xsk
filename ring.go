package xsk

import (
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

func XskRingProdFillAddr(fill *XskRingProd, idx uint32) *uint64 {
	addrs := unsafe.Slice((*uint64)(fill.Ring), int(fill.Size))
	return &addrs[idx&fill.Mask]
}

func XskRingConsCompAddr(comp *XskRingCons, idx uint32) *uint64 {
	addrs := unsafe.Slice((*uint64)(comp.Ring), int(comp.Size))
	return &addrs[idx&comp.Mask]
}

func XskRingProdTxDesc(tx *XskRingProd, idx uint32) *unix.XDPDesc {
	descs := unsafe.Slice((*unix.XDPDesc)(tx.Ring), int(tx.Size))
	return &descs[idx&tx.Mask]
}

func XskRingConsRxDesc(rx *XskRingCons, idx uint32) *unix.XDPDesc {
	descs := unsafe.Slice((*unix.XDPDesc)(rx.Ring), int(rx.Size))
	return &descs[idx&rx.Mask]
}

func XskRingProdNeedsWakeup(r *XskRingProd) bool {
	return *r.Flags&unix.XDP_RING_NEED_WAKEUP != 0
}

func XskProdNbFree(r *XskRingProd, nb uint32) uint32 {
	freeEntries := r.CachedCons - r.CachedProd

	if freeEntries >= nb {
		return freeEntries
	}
	/*
		刷新本地尾指针。
		cached_cons 比实际的消费者指针大 r->size，这样在更频繁执行的代码中可以避免这个加法运算，该代码在函数开头计算 free_entries。
		如果没有这个优化，那么 free_entries 将是 free_entries = r->cached_prod - r->cached_cons + r->size
	*/
	r.CachedCons = atomic.LoadUint32(r.Consumer)
	r.CachedCons += r.Size

	return r.CachedCons - r.CachedProd
}

func XskConsNbAvail(r *XskRingCons, nb uint32) uint32 {
	entries := r.CachedProd - r.CachedCons

	if entries == 0 {
		r.CachedProd = atomic.LoadUint32(r.Producer)
		entries = r.CachedProd - r.CachedCons
	}

	if entries > nb {
		return nb
	}
	return entries
}

func XskRingProdReserve(prod *XskRingProd, nb uint32, idx *uint32) uint32 {
	if XskProdNbFree(prod, nb) < nb {
		return 0
	}

	*idx = prod.CachedProd
	prod.CachedProd += nb

	return nb
}

func XskRingProdSubmit(prod *XskRingProd, nb uint32) {
	atomic.AddUint32(prod.Producer, nb)
}

func XskRingConsPeek(cons *XskRingCons, nb uint32, idx *uint32) uint32 {
	entries := XskConsNbAvail(cons, nb)

	if entries > 0 {
		*idx = cons.CachedCons
		cons.CachedCons += entries
	}

	return entries
}

func XskRingConsCancel(cons *XskRingCons, nb uint32) {
	cons.CachedCons -= nb
}

func XskRingConsRelease(cons *XskRingCons, nb uint32) {
	atomic.AddUint32(cons.Consumer, nb)
}

func XskUmemGetData(umemArea unsafe.Pointer, addr uint64) unsafe.Pointer {
	return unsafe.Pointer(uintptr(umemArea) + uintptr(addr))
}

func XskUmemExtractAddr(addr uint64) uint64 {
	return addr & XSK_UNALIGNED_BUF_ADDR_MASK
}

func XskUmemExtractOffset(addr uint64) uint64 {
	return addr >> XSK_UNALIGNED_BUF_OFFSET_SHIFT
}

func XskUmemAddOffsetToAddr(addr uint64) uint64 {
	return XskUmemExtractAddr(addr) + XskUmemExtractOffset(addr)
}
