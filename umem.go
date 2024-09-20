package xsk

import (
	"container/list"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// XskUmemCreate 初始化一个 XskUmem 对象，并使用给定的参数进行配置。
//
// 参数:
// - umemArea: 指向用于 umem 的内存区域的指针。
// - size: umem 区域的大小。
// - fill: 指向用于填充环的 XskRingProd 结构体的指针。
// - comp: 指向用于完成环的 XskRingCons 结构体的指针。
// - usrConfig: 指向用户配置的 XskUmemConfig 结构体的指针。
//
// 返回值:
// - 指向创建的 XskUmem 对象的指针。
// - 如果创建失败，则返回错误信息。
func XskUmemCreate(umemArea unsafe.Pointer, size uint64, fill *XskRingProd, comp *XskRingCons, usrConfig *XskUmemConfig) (*XskUmem, error) {
	return XskUmemCreateWithFd(-1, umemArea, size, fill, comp, usrConfig)
}

// XskUmemCreateWithFd 创建一个 XskUmem 实例，并将其注册到内核中对应的套接字。
// 参数：
//   - fd: 套接字文件描述符。如果为负数，则函数内部会创建一个新的套接字。
//   - umemArea: 指向 umem 区域的指针。
//   - size: umem 区域的大小。
//   - fill: 指向 XskRingProd 结构体的指针，用于填充环。
//   - comp: 指向 XskRingCons 结构体的指针，用于完成环。
//   - usrConfig: 指向 XskUmemConfig 结构体的指针，用于用户配置。
//
// 返回值：
//   - 成功时返回指向 XskUmem 结构体的指针，失败时返回错误信息。
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
	// 初始化 umem，每一个 umem 都要绑定一个 socket
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
		err = fmt.Errorf("unix.Setsockopt XDP_UMEM_REG 失败: %v", errno)
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

// xskSetUmemConfig 配置 XskUmemConfig 结构体。
// 如果 usrCfg 为 nil，则使用默认值初始化 cfg。
// 否则，将 usrCfg 的值复制到 cfg。
// 参数:
//   - cfg: 指向 XskUmemConfig 结构体的指针，用于存储配置。
//   - usrCfg: 指向 XskUmemConfig 结构体的指针，包含用户提供的配置。如果为 nil，则使用默认配置。
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

// xskCreateUmemRings 创建并初始化 XDP UMEM 的 fill ring 和 completion ring。
//
// 参数:
// - umem: 指向 XskUmem 结构体的指针，包含 UMEM 的配置信息。
// - fd: 套接字文件描述符。
// - fill: 指向 XskRingProd 结构体的指针，用于 fill ring 的生产者环。
// - comp: 指向 XskRingCons 结构体的指针，用于 completion ring 的消费者环。
//
// 返回:
// - error: 如果操作失败，返回错误信息；成功则返回 nil。
//
// 该函数执行以下操作:
// 1. 设置 fill ring 和 completion ring 的大小。
// 2. 获取各个 ring 中字段的偏移值。
// 3. 将内核中分配的 fill ring 和 completion ring 的地址映射到用户态。
// 4. 初始化用户态维护的 fill ring 和 completion ring 结构体。
func xskCreateUmemRings(umem *XskUmem, fd int, fill *XskRingProd, comp *XskRingCons) error {
	// 获取偏移值，偏移值都是相对于结构体的起始位置的偏移
	var off unix.XDPMmapOffsets
	var err error
	// 设置 fill ring 的大小，设置后内核会给 fd 对应的套接字分配 fill ring 的结构体
	err = unix.SetsockoptInt(fd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING, int(umem.Config.FillSize))
	if err != nil {
		return fmt.Errorf("unix.SetsockoptInt XDP_UMEM_FILL_RING 失败: %v", err)
	}
	// 设置 completion ring 的大小，设置后内核会给 fd 对应的套接字分配 completion ring 的结构体
	err = unix.SetsockoptInt(fd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING, int(umem.Config.CompSize))
	if err != nil {
		return fmt.Errorf("unix.SetsockoptInt XDP_UMEM_COMPLETION_RING 失败: %v", err)
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
		return fmt.Errorf("unix.Mmap fillMap 失败: %v", err)
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
		return fmt.Errorf("unix.Mmap compMap 失败: %v", err)
	}
	comp.Mask = umem.Config.CompSize - 1
	comp.Size = umem.Config.CompSize
	comp.Producer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&compMap[0])) + uintptr(off.Cr.Producer)))
	comp.Consumer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&compMap[0])) + uintptr(off.Cr.Consumer)))
	comp.Flags = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&compMap[0])) + uintptr(off.Cr.Flags)))
	comp.Ring = unsafe.Pointer(uintptr(unsafe.Pointer(&compMap[0])) + uintptr(off.Cr.Desc))
	return nil
}

// xskGetMmapOffsets 获取指定文件描述符的 XDP 内存映射偏移量（内核版本 >= 5.4）。
// 注意，内核版本 <= 5.3 的系统中，getsocketopt 没有 flag 字段，需要进一步处理，这里暂不支持 <= 5.3 的内核
// 参数:
//   - fd: 文件描述符。
//
// 返回值:
//   - unix.XDPMmapOffsets: 包含内存映射偏移量的结构体。
//   - error: 如果调用失败，返回错误信息。
func xskGetMmapOffsets(fd int) (unix.XDPMmapOffsets, error) {
	var offsets unix.XDPMmapOffsets
	var vallen = uint32(unsafe.Sizeof(offsets))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd),
		unix.SOL_XDP, unix.XDP_MMAP_OFFSETS,
		uintptr(unsafe.Pointer(&offsets)),
		uintptr(unsafe.Pointer(&vallen)), 0)
	if errno != 0 {
		return offsets, fmt.Errorf("unix.Syscall6 getsockopt XDP_MMAP_OFFSETS 失败: %v", errno)
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
