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

// xskLookupMap 搜索与给定 eBPF 程序关联的 eBPF map，并匹配提供的过滤函数。
//
// 参数：
//   - prog: 指向 eBPF 程序的指针，用于检索 map 信息。
//   - mapInfoFilter: 一个函数，接受一个指向 ebpf.MapInfo 的指针，并返回一个布尔值，
//     指示 map 是否符合所需的标准。
//
// 返回值：
// - 一个指向符合过滤条件的 eBPF map 的指针，如果没有找到匹配的 map，则返回 nil。
// - 如果检索程序或 map 信息时出现问题，则返回错误。
//
// 该函数迭代与提供的 eBPF 程序关联的 map ID，检索每个 map，并将过滤函数应用于 map 的信息。
// 如果一个 map 符合过滤条件，则返回 map 的克隆。如果没有找到匹配的 map，则函数返回 nil。
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

// xskUpdateProgRefcnt 更新提供的 map 中 eBPF 程序的引用计数。
// 它在执行更新之前获取锁，并在之后释放锁。
//
// 参数：
// - refcntMap: 指向包含引用计数的 eBPF map 的指针。
// - delta: 增加或减少引用计数的值。
//
// 返回值：
// - int: 更新后的引用计数，如果发生错误则为 -1。
// - error: 如果发生错误，则返回错误对象，否则为 nil。
//
// 注意：
// - map 的 key 始终为零。
// - 如果引用计数为零，程序正在等待分离，不能使用。
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

// xskSetupXdpProg 设置给定 XskSocket 的 XDP 程序，并在提供时更新 xsksMap。
// 它执行以下步骤：
// 1. 检查网络接口是否已附加 XDP 程序。
// 2. 如果已附加 XDP 程序，则尝试加载该程序并增加其引用计数。
// 3. 如果没有附加 XDP 程序或引用计数为零，则卸载该XDP程序，并加载新的 XDP 程序。
// 4. 将新的 XDP 程序附加到网络接口并固定它。
// 5. 查找与 XDP 程序关联的引用计数 map 和 xsks map。
// 6. 使用 XskSocket 的 Rx 队列的文件描述符更新 xsks map。
// 7. 如果需要 xsksMap，则克隆 xsks map 并将其分配给 xsksMap。
//
// 参数：
// - xsk: 指向 XskSocket 结构的指针。
// - xsksMap: 指向 eBPF map 指针的指针，如果提供，将使用 xsks map 更新它。
//
// 返回值：
// - error: 如果设置过程中的任何步骤失败，则返回错误。
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

// xskReleaseXdpProg 释放与给定 XskSocket 关联的 XDP (eXpress Data Path) 程序。
// 它执行以下步骤：
// 1. 检查引用计数 map 是否为 nil，如果是则退出。
// 2. 减少程序引用计数并关闭引用计数 map。
// 3. 如果有错误或引用计数不为零，则退出。
// 4. 通过索引检索网络链接。
// 5. 加载与 XDP 程序 ID 关联的固定链接，如果成功则取消固定并关闭它。
// 6. 关闭 XDP 程序并将其设置为 nil。
//
// 参数：
// - xsk: 包含上下文和 XDP 程序信息的 XskSocket 结构的指针。
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
	if err != nil || value != 0 {
		goto out
	}

	ifLink, err = netlink.LinkByIndex(ctx.Ifindex)
	if err != nil {
		goto out
	}

	l, err = link.LoadPinnedLink(fmt.Sprint(LinkPath, ifLink.Attrs().Xdp.ProgId), nil)
	if err == nil {
		l.Unpin()
		l.Close()
	}

out:
	ctx.XdpProg.Close()
	ctx.XdpProg = nil
}
