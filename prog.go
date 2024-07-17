package xsk

import (
	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS xsk_def_xdp_prog ./xdp/xsk_def_xdp_prog.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS xsk_def_xdp_prog_5_3 ./xdp/xsk_def_xdp_prog_5.3.c

func XskSetupXdpProg(ifindex int, xsksMapFd *int) error {
	xsk := new(XskSocket)
	err := XskInitXskStruct(xsk, ifindex)
	if err != nil {
		return err
	}
	err = xskSetupXdpProg(xsk, xsksMapFd)
	xskDestroyXskStruct(xsk)
	return err
}

// 对应函数 xsk_socket__update_xskmap
func XskSocketUpdateXskmap(xsk *XskSocket, xsksMapFd int) error {
	// TODO: 待实现
	panic("implement me")
}

func xskSetupXdpProg(xsk *XskSocket, xsksMapFd *int) error {
	// TODO: 加载xdp程序
	panic("implement me")

}

// 对应函数 xsk_delete_map_entry
func xskDeleteMapEntry(xsksMapFd int, queueID uint32) error {
	xsksMap, err := ebpf.NewMapFromFD(xsksMapFd)
	if err != nil {
		return err
	}
	err = xsksMap.Delete(&queueID)
	if err != nil {
		return err
	}
	xsksMap.Close()
	return nil
}

// 对应函数 xsk_release_xdp_prog
func xskReleaseXdpProg(xsk *XskSocket) {
	// TODO: 待实现
	panic("implement me")
}

// func xskLookupProgram(ifindex int) (*ebpf.Program, error) {
// 	versionName := "xsk_prog_version"
// 	progName := "xsk_def_prog"

// 	// libxdp 实现了多程序挂载，这里需要看一下libxdp实现的方法
// 	link, err := netlink.LinkByIndex(20)
// 	if err != nil {
// 		return nil, nil
// 	}
// 	fmt.Println(link)
// 	prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(link.Attrs().Xdp.ProgId))
// 	if err != nil {
// 		return nil, err
// 	}
// 	info := prog.Info()
// }
