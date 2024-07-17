package xsk

import (
	"container/list"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

/*
	type XskUmem struct {
		FillSave        *XskRingProd 初始化等于fill
		CompSave        *XskRingCons 初始化等于comp
		UmemArea        unsafe.Pointer 初始化等于umemArea
		Config          XskUmemConfig 初始化等于usrConfig或者默认config
		Fd              int 初始创建一个socket的fd
		Refcount        int 未显式初始化，默认为 0
		CtxList         []XskCtx 空列表
		RxRingSetupDone bool 未显式初始化，默认为false
		TxRingSetupDone bool 未显式初始化，默认为false
	}
*/
func XskUmemCreate(umemArea unsafe.Pointer, size uint64, fill *XskRingProd, comp *XskRingCons, usrConfig *XskUmemConfig) (*XskUmem, error) {
	return XskUmemCreateWithFd(-1, umemArea, size, fill, comp, usrConfig)
}

func XskUmemCreateWithFd(fd int, umemArea unsafe.Pointer, size uint64, fill *XskRingProd, comp *XskRingCons, usrConfig *XskUmemConfig) (*XskUmem, error) {
	// 用于注册 umem 信息，与内核交互的结构体
	var mr unix.XDPUmemReg
	var umem *XskUmem
	var err error
	// 参数检查
	if umemArea == nil || fill == nil || comp == nil {
		return nil, unix.EFAULT
	}
	if size == 0 && !xskPageAligned(umemArea) {
		return nil, unix.EINVAL
	}
	// 分配空间
	umem = new(XskUmem)
	// 初始化 umem
	if fd < 0 {
		umem.Fd, err = unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
		if err != nil {
			return nil, err
		}
	} else {
		umem.Fd = fd
	}
	umem.UmemArea = umemArea
	umem.CtxList = list.New()
	// 将 usrConfig 复制到 umem.Config 中（如果 usrConfig 为 NULL，则载入默认配置到 umem.Config 中）
	xskSetUmemConfig(&umem.Config, usrConfig)

	mr.Addr = uint64(uintptr(umemArea))
	mr.Len = size
	mr.Chunk_size = umem.Config.FrameSize
	mr.Headroom = umem.Config.FrameHeadroom
	mr.Flags = umem.Config.Flags

	// 将 umem 注册给内核中对应的套接字 umem->fd
	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(umem.Fd),
		unix.SOL_XDP, unix.XDP_UMEM_REG,
		uintptr(unsafe.Pointer(&mr)),
		unsafe.Sizeof(mr), 0)
	if errno != 0 {
		err = fmt.Errorf("unix.Setsockopt XDP_UMEM_REG failed: %v", errno)
		goto out_socket
	}
	// 创建 fill_ring 和 completion_ring，绑定到 umem->fd 的套接字，使用 umem-> config 的信息
	err = xskCreateUmemRings(umem, umem.Fd, fill, comp)
	if err != nil {
		goto out_socket
	}
	// 暂存创建的 fill_ring 和 completion_ring
	umem.FillSave = fill
	umem.CompSave = comp
	return umem, nil

out_socket:
	unix.Close(umem.Fd)
	return nil, err
}

func xskSetUmemConfig(cfg *XskUmemConfig, usrCfg *XskUmemConfig) {
	if usrCfg == nil {
		cfg.FillSize = XSK_RING_PROD__DEFAULT_NUM_DESCS
		cfg.CompSize = XSK_RING_CONS__DEFAULT_NUM_DESCS
		cfg.FrameSize = XSK_UMEM__DEFAULT_FRAME_SIZE
		cfg.FrameHeadroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM
		cfg.Flags = XSK_UMEM__DEFAULT_FLAGS
		return
	}
	cfg.FillSize = usrCfg.FillSize
	cfg.CompSize = usrCfg.CompSize
	cfg.FrameSize = usrCfg.FrameSize
	cfg.FrameHeadroom = usrCfg.FrameHeadroom
	cfg.Flags = usrCfg.Flags
}

func xskCreateUmemRings(umem *XskUmem, fd int, fill *XskRingProd, comp *XskRingCons) error {
	// 获取偏移值，偏移值都是相对于结构体的起始位置的偏移
	var off unix.XDPMmapOffsets
	var err error
	// 设置 fill ring 的大小，设置后内核会给 fd 对应的套接字分配 fill ring 的结构体
	err = unix.SetsockoptInt(fd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING, int(umem.Config.FillSize))
	if err != nil {
		return fmt.Errorf("unix.SetsockoptInt XDP_UMEM_FILL_RING failed: %v", err)
	}
	// 设置 completion ring 的大小，设置后内核会给 fd 对应的套接字分配 completion ring 的结构体
	err = unix.SetsockoptInt(fd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING, int(umem.Config.CompSize))
	if err != nil {
		return fmt.Errorf("unix.SetsockoptInt XDP_UMEM_COMPLETION_RING failed: %v", err)
	}
	// 获取各个ring中各个字段的偏移值（内核版本 >= 5.4）
	off, err = xskGetMmapOffsets(fd)
	if err != nil {
		return err
	}
	/*
		将内核中分配的 fill ring 的地址，映射到 fillMap 中（现在 map 就相当于 fd 的 fill_ring 结构体的起始地址）
		关于长度的计算，内核中实际的结构体如下：
		struct xdp_ring {
			u32 producer ____cacheline_aligned_in_smp;
			u32 pad1 ____cacheline_aligned_in_smp;
			u32 consumer ____cacheline_aligned_in_smp;
			u32 pad2 ____cacheline_aligned_in_smp;
			u32 flags;
			u32 pad3 ____cacheline_aligned_in_smp;
		};
		struct xdp_umem_ring {
			struct xdp_ring ptrs;
			u64 desc[] ____cacheline_aligned_in_smp;
		};
		desc 是结构体中最后一个位置，并且是 u64 的数组，这样关于长度的计算就很好理解了
	*/
	fillMap, err := unix.Mmap(fd, unix.XDP_UMEM_PGOFF_FILL_RING,
		int(off.Fr.Desc+uint64(umem.Config.FillSize)*uint64(unsafe.Sizeof(uint64(0)))),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return fmt.Errorf("unix.Mmap failed: %v", err)
	}
	// 设置用户态维护的 fill 结构体，其中和内核态 fill_ring 相关的部分使用偏移
	fill.Mask = umem.Config.FillSize - 1
	fill.Size = umem.Config.FillSize
	fill.Producer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&fillMap[0])) + uintptr(off.Fr.Producer)))
	fill.Consumer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&fillMap[0])) + uintptr(off.Fr.Consumer)))
	fill.Flags = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&fillMap[0])) + uintptr(off.Fr.Flags)))
	fill.Ring = unsafe.Pointer(uintptr(unsafe.Pointer(&fillMap[0])) + uintptr(off.Fr.Desc))
	fill.CachedProd = umem.Config.FillSize

	// 同理设置 comp 队列
	compMap, err := unix.Mmap(fd, unix.XDP_UMEM_PGOFF_COMPLETION_RING,
		int(off.Cr.Desc+uint64(umem.Config.CompSize)*uint64(unsafe.Sizeof(uint64(0)))),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		unix.Munmap(fillMap)
		return fmt.Errorf("unix.Mmap failed: %v", err)
	}
	comp.Mask = umem.Config.CompSize - 1
	comp.Size = umem.Config.CompSize
	comp.Producer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&compMap[0])) + uintptr(off.Cr.Producer)))
	comp.Consumer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&compMap[0])) + uintptr(off.Cr.Consumer)))
	comp.Flags = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&compMap[0])) + uintptr(off.Cr.Flags)))
	comp.Ring = unsafe.Pointer(uintptr(unsafe.Pointer(&compMap[0])) + uintptr(off.Cr.Desc))
	return nil
}

// 获取各个ring中各个字段的偏移值（内核版本 >= 5.4）
// 注意，内核版本 <= 5.3 的系统中，getsocketopt 没有 flag 字段，需要进一步处理，这里暂不支持 <= 5.3 的内核
func xskGetMmapOffsets(fd int) (unix.XDPMmapOffsets, error) {
	var offsets unix.XDPMmapOffsets
	var vallen = uint32(unsafe.Sizeof(offsets))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd),
		unix.SOL_XDP, unix.XDP_MMAP_OFFSETS,
		uintptr(unsafe.Pointer(&offsets)),
		uintptr(unsafe.Pointer(&vallen)), 0)
	if errno != 0 {
		return offsets, fmt.Errorf("unix.Syscall6 getsockopt XDP_MMAP_OFFSETS failed: %v", errno)
	}
	return offsets, nil
}

func XskUmemDelete(umem *XskUmem) error {
	var off unix.XDPMmapOffsets
	var err error
	if umem == nil {
		return nil
	}

	if umem.Refcount > 0 {
		return unix.EBUSY
	}

	off, err = xskGetMmapOffsets(umem.Fd)
	if err == nil && umem.FillSave != nil && umem.CompSave != nil {
		unix.Munmap(unsafe.Slice((*byte)(unsafe.Pointer(uintptr(umem.FillSave.Ring)-uintptr(off.Fr.Desc))),
			int(off.Fr.Desc+uint64(umem.Config.FillSize)*uint64(unsafe.Sizeof(uint64(0))))))
		unix.Munmap(unsafe.Slice((*byte)(unsafe.Pointer(uintptr(umem.CompSave.Ring)-uintptr(off.Cr.Desc))),
			int(off.Cr.Desc+uint64(umem.Config.CompSize)*uint64(unsafe.Sizeof(uint64(0))))))
	}
	unix.Close(umem.Fd)
	return nil
}
