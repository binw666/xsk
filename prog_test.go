package xsk

import (
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

func TestAdd(t *testing.T) {
	ifaceName := "ens1"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		t.Fatal(err)
	}

	// 载入内核
	obj := &xsk_def_xdp_progObjects{}
	err = loadXsk_def_xdp_progObjects(obj, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Close()
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   obj.XskDefProg,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	link, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(link.Attrs().Xdp.ProgId))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(prog)
	info, err := prog.Info()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(info)
	maps, has := info.MapIDs()
	// 这里与libbpf的实现不同，libbpf会使用 BPF 对象名称的前 8 个字符加上一个表示内部映射类型的后缀，例如 "xdp_def_" + ".data"。
	// 而这里，只有 .data
	if has {
		for _, id := range maps {
			mapObj, err := ebpf.NewMapFromID(ebpf.MapID(id))
			if err != nil {
				t.Fatal(err)
			}
			fmt.Println(mapObj)
			fmt.Println(mapObj.Info())
		}
	}

	btfID, has := info.BTFID()
	if has {
		handle, err := btf.NewHandleFromID(btfID)
		if err != nil {
			t.Fatal(err)
		}
		spec, err := handle.Spec(nil)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(spec)
	}

}
