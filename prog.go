package xsk

import (
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

const LinkPath = "/sys/fs/bpf/xsk_def_xdp_prog_"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS xsk_def_xdp_prog ./xdp/xsk_def_xdp_prog.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS xsk_def_xdp_prog_5_3 ./xdp/xsk_def_xdp_prog_5.3.c

func XskSetupXdpProg(ifindex int, xsksMap **ebpf.Map) error {
	xsk := new(XskSocket)
	err := XskInitXskStruct(xsk, ifindex)
	if err != nil {
		return err
	}
	err = xskSetupXdpProg(xsk, xsksMap)
	xskDestroyXskStruct(xsk)
	return err
}

// 对应函数 xsk_socket__update_xskmap
func XskSocketUpdateXskmap(xsk *XskSocket, xsksMapFd int) error {
	// TODO: 待实现
	panic("implement me")
}

func xskMapIsRefcntMap(mapInfo *ebpf.MapInfo) bool {
	// 检查 map 名称是否以 ".data" 开头，并且 valueSize 大于等于 int 类型的大小
	return strings.HasPrefix(mapInfo.Name, ".data") &&
		mapInfo.ValueSize >= uint32(unsafe.Sizeof(uint32(0)))
}
func xskMapIsSocketMap(mapInfo *ebpf.MapInfo) bool {
	// 检查 map 名称是否以 ".data" 开头，并且 valueSize 大于等于 int 类型的大小
	return strings.HasPrefix(mapInfo.Name, "xsks_map") &&
		mapInfo.KeySize == 4 && mapInfo.ValueSize == 4
}

func xskLookupMap(prog *ebpf.Program, mapInfoFilter func(*ebpf.MapInfo) bool) (*ebpf.Map, error) {
	info, err := prog.Info()
	if err != nil {
		return nil, err
	}
	maps, has := info.MapIDs()
	if has {
		for _, id := range maps {
			mapObj, err := ebpf.NewMapFromID(ebpf.MapID(id))
			if err != nil {
				continue
			}
			defer mapObj.Close()
			mapInfo, err := mapObj.Info()
			if err != nil {
				continue
			}
			if mapInfoFilter(mapInfo) {
				return mapObj.Clone()
			}
		}
	}
	return nil, nil
}

func xskLookupRefcntMap(prog *ebpf.Program) (*ebpf.Map, error) {
	return xskLookupMap(prog, xskMapIsRefcntMap)
}

func xskLookupBPFMap(prog *ebpf.Program) (*ebpf.Map, error) {
	return xskLookupMap(prog, xskMapIsSocketMap)
}

func xskUpdateProgRefcnt(refcntMap *ebpf.Map, delta int) (int, error) {
	var err error
	var ret int = -1
	var key uint32 = 0
	var valueData []byte
	var value int
	lockFile, err := xdpLockAcquire()
	if err != nil {
		goto out
	}
	/* Note, if other global variables are added before the refcnt,
	 * this changes map's value type, not number of elements,
	 * so additional offset must be applied to value_data,
	 * when reading refcount, but map key always stays zero
	 */
	valueData, err = refcntMap.LookupBytes(&key)
	if err != nil {
		goto unlock
	}

	value = int(binary.LittleEndian.Uint32(valueData))
	/* If refcount is 0, program is awaiting detach and can't be used */
	if value != 0 {
		value += delta
		binary.LittleEndian.PutUint32(valueData, uint32(value))
		err := refcntMap.Update(&key, valueData, ebpf.UpdateAny)
		if err != nil {
			goto unlock
		}
	}

	ret = value
unlock:
	xdpLockRelease(lockFile)
out:
	return ret, err

}

func xskIncrProgRefcnt(refcntMap *ebpf.Map) (int, error) {
	return xskUpdateProgRefcnt(refcntMap, 1)
}

func xskDecrProgRefcnt(refcntMap *ebpf.Map) (int, error) {
	return xskUpdateProgRefcnt(refcntMap, -1)
}

func xskSetupXdpProg(xsk *XskSocket, xsksMap **ebpf.Map) error {
	ctx := xsk.Ctx
	attached := false
	var err error
	var bpfInfo *ebpf.ProgramInfo
	var bpfID ebpf.ProgramID
	var supportProgID bool
	var l link.Link

	ifLink, err := netlink.LinkByIndex(ctx.Ifindex)
	if err != nil {
		return err
	}
	if ifLink.Attrs().Xdp.Attached {
		var refcnt int
		ctx.XdpProg, err = ebpf.NewProgramFromID(ebpf.ProgramID(ifLink.Attrs().Xdp.ProgId))
		if err != nil {
			goto err_prog_load
		}
		ctx.RefcntMap, err = xskLookupRefcntMap(ctx.XdpProg)
		// 查找过程中出错
		if err != nil {
			goto err_prog_load
		}
		// 没找到对应的map
		if ctx.RefcntMap == nil {
			goto map_lookup
		}
		refcnt, err = xskIncrProgRefcnt(ctx.RefcntMap)
		if err != nil {
			goto err_prog_load
		}

		if refcnt == 0 {
			// Current program is being detached, falling back on creating a new program
			ctx.RefcntMap.Close()
			ctx.RefcntMap = nil
			ctx.XdpProg.Close()
			ctx.XdpProg = nil
			// 解除之前的 hook
			l, err = link.LoadPinnedLink(fmt.Sprint(LinkPath, ifLink.Attrs().Xdp.ProgId), nil)
			if err != nil {
				log.Println(err)
			}
			l.Unpin()
			l.Close()
		}
	}

	if ctx.XdpProg == nil {
		// 注意：这里默认载入 5.3 以上的
		spec, err := loadXsk_def_xdp_prog()
		if err != nil {
			return err
		}
		// 获取最大RX队列
		channel, err := GetEthChannels(ctx.Ifname)
		if err != nil {
			return err
		}
		if myMapSpec, ok := spec.Maps["xsks_map"]; ok {
			myMapSpec.MaxEntries = channel.MaxRX
		}
		obj := xsk_def_xdp_progObjects{}
		err = spec.LoadAndAssign(&obj, nil)
		if err != nil {
			return err
		}
		defer obj.Close()
		ctx.XdpProg, err = obj.XskDefProg.Clone()
		if err != nil {
			goto err_prog_load
		}
		bpfInfo, err = ctx.XdpProg.Info()
		if err != nil {
			goto err_prog_load
		}
		if bpfID, supportProgID = bpfInfo.ID(); !supportProgID {
			goto err_prog_load
		}

		l, err := link.AttachXDP(link.XDPOptions{
			Program:   ctx.XdpProg,
			Interface: ctx.Ifindex,
			Flags:     xsk.Config.XdpFlags,
		})
		if err != nil {
			goto err_prog_load
		}
		if l.Pin(fmt.Sprint(LinkPath, bpfID)) != nil {
			goto err_prog_load
		}
		l.Close()
		attached = true

	}

	if ctx.RefcntMap == nil {
		ctx.RefcntMap, err = xskLookupRefcntMap(ctx.XdpProg)
		if err != nil || ctx.RefcntMap == nil {
			goto err_prog_load
		}
	}
map_lookup:
	ctx.XsksMap, err = xskLookupBPFMap(ctx.XdpProg)
	if err != nil {
		goto err_lookup
	}
	if xsk.Rx != nil {
		err = ctx.XsksMap.Update(ctx.QueueId, int32(xsk.Fd), ebpf.UpdateAny)
		if err != nil {
			goto err_lookup
		}
	}

	if xsksMap != nil {
		*xsksMap, _ = ctx.XsksMap.Clone()
	}
	return nil

err_lookup:
	if attached {
		l, err = link.LoadPinnedLink(fmt.Sprint(LinkPath, ifLink.Attrs().Xdp.ProgId), nil)
		if err != nil {
			log.Println(err)
		}
		l.Unpin()
		l.Close()
	}

err_prog_load:
	if ctx.RefcntMap != nil {
		ctx.RefcntMap.Close()
		ctx.RefcntMap = nil
	}
	ctx.XdpProg.Close()
	ctx.XdpProg = nil
	return err
}

// 对应函数 xsk_release_xdp_prog
func xskReleaseXdpProg(xsk *XskSocket) {
	var ifLink netlink.Link
	var err error
	var value int
	var l link.Link
	ctx := xsk.Ctx

	if ctx.RefcntMap == nil {
		goto out
	}

	value, err = xskDecrProgRefcnt(ctx.RefcntMap)
	ctx.RefcntMap.Close()
	ctx.RefcntMap = nil
	if err != nil {
		goto out
	}

	if value != 0 {
		goto out
	}

	ifLink, err = netlink.LinkByIndex(ctx.Ifindex)
	if err != nil {
		goto out
	}

	l, err = link.LoadPinnedLink(fmt.Sprint(LinkPath, ifLink.Attrs().Xdp.ProgId), nil)
	if err != nil {
		log.Println(err)
	}

	l.Unpin()
	l.Close()

out:
	ctx.XdpProg.Close()
	ctx.XdpProg = nil
}
