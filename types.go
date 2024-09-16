package xsk

import (
	"container/list"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

/*
#define DEFINE_XSK_RING(name) \

	struct name { \
		__u32 cached_prod; \
		__u32 cached_cons; \
		__u32 mask; \
		__u32 size; \
		__u32 *producer; \
		__u32 *consumer; \
		void *ring; \
		__u32 *flags; \
	}

DEFINE_XSK_RING(xsk_ring_prod);
*/
type XskRingProd struct {
	CachedProd uint32
	CachedCons uint32
	Mask       uint32
	Size       uint32
	Producer   *uint32
	Consumer   *uint32
	Ring       unsafe.Pointer
	Flags      *uint32
}

/*
#define DEFINE_XSK_RING(name) \

	struct name { \
		__u32 cached_prod; \
		__u32 cached_cons; \
		__u32 mask; \
		__u32 size; \
		__u32 *producer; \
		__u32 *consumer; \
		void *ring; \
		__u32 *flags; \
	}

DEFINE_XSK_RING(xsk_ring_cons);
*/
type XskRingCons struct {
	CachedProd uint32
	CachedCons uint32
	Mask       uint32
	Size       uint32
	Producer   *uint32
	Consumer   *uint32
	Ring       unsafe.Pointer
	Flags      *uint32
}

/*
	struct xsk_umem_config {
		__u32 fill_size;
		__u32 comp_size;
		__u32 frame_size;
		__u32 frame_headroom;
		__u32 flags;
	};
*/
type XskUmemConfig struct {
	FillSize      uint32
	CompSize      uint32
	FrameSize     uint32
	FrameHeadroom uint32
	Flags         uint32
}

/*
	struct xsk_ctx {
		struct xsk_ring_prod *fill;
		struct xsk_ring_cons *comp;
		struct xsk_umem *umem;
		__u32 queue_id;
		int refcount;
		int ifindex;
		__u64 netns_cookie;
		int xsks_map_fd;
		struct list_head list;
		struct xdp_program *xdp_prog;
		int refcnt_map_fd;
		char ifname[IFNAMSIZ];
	};
*/
type XskCtx struct {
	Fill        *XskRingProd
	Comp        *XskRingCons
	Umem        *XskUmem
	QueueId     uint32
	Refcount    int
	Ifindex     int
	NetnsCookie uint64
	XsksMap     *ebpf.Map
	XdpProg     *ebpf.Program
	RefcntMap   *ebpf.Map
	Ifname      string
}

/*
	struct xsk_umem {
		struct xsk_ring_prod *fill_save;
		struct xsk_ring_cons *comp_save;
		char *umem_area;
		struct xsk_umem_config config;
		int fd;
		int refcount;
		struct list_head ctx_list;
		bool rx_ring_setup_done;
		bool tx_ring_setup_done;
	};
*/
type XskUmem struct {
	FillSave        *XskRingProd
	CompSave        *XskRingCons
	UmemArea        unsafe.Pointer
	Config          XskUmemConfig
	Fd              int
	Refcount        int
	CtxList         *list.List
	RxRingSetupDone bool
	TxRingSetupDone bool
}

/*
	struct xsk_socket_config {
		__u32 rx_size;
		__u32 tx_size;
		union {
			__u32 libbpf_flags;
			__u32 libxdp_flags;
		};
		__u32 xdp_flags;
		__u16 bind_flags;
	};
*/
type XskSocketConfig struct {
	RxSize      uint32
	TxSize      uint32
	LibbpfFlags uint32
	XdpFlags    link.XDPAttachFlags
	BindFlags   uint16
}

/*
	struct xsk_socket {
		struct xsk_ring_cons *rx;
		struct xsk_ring_prod *tx;
		struct xsk_ctx *ctx;
		struct xsk_socket_config config;
		int fd;
	};
*/
type XskSocket struct {
	Rx     *XskRingCons
	Tx     *XskRingProd
	Ctx    *XskCtx
	Config XskSocketConfig
	Fd     int
}
