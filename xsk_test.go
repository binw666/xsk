package xsk

import (
	"log"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func TestXskRecv(t *testing.T) {
	iface := "ens1"
	NumFrames := 2048
	FrameSize := 4096

	ethChan, err := GetEthChannels(iface)
	if err != nil {
		log.Fatal("get queue error:", err)
	}

	for queueID := 0; queueID < int(ethChan.TXCount); queueID++ {
		log.Println("正在初始化：", queueID)
		umemArea, err := unix.Mmap(-1, 0, NumFrames*FrameSize,
			unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE)
		if err != nil {
			log.Fatal("mmap error:", err)
		}
		defer unix.Munmap(umemArea)
		fill := XskRingProd{}
		comp := XskRingCons{}
		umem, err := XskUmemCreate(unsafe.Pointer(&umemArea[0]), uint64(NumFrames*FrameSize), &fill, &comp, &XskUmemConfig{
			FillSize:      uint32(NumFrames / 2),
			CompSize:      uint32(NumFrames / 2),
			FrameSize:     uint32(FrameSize),
			FrameHeadroom: uint32(0),
			Flags:         uint32(0),
		})
		if err != nil {
			log.Fatal("umem create error", err)
		}
		defer XskUmemDelete(umem)
		rx := XskRingCons{}
		tx := XskRingProd{}
		socket, err := XskSocketCreate(iface, uint32(queueID), umem, &rx, &tx, &XskSocketConfig{
			RxSize:      uint32(NumFrames / 2),
			TxSize:      uint32(NumFrames / 2),
			XdpFlags:    link.XDPGenericMode,
			BindFlags:   unix.XDP_USE_NEED_WAKEUP,
			LibbpfFlags: 0,
		})
		if err != nil {
			log.Fatal("socket create error", err)
		}
		defer XskSocketDelete(socket)
		pos := uint32(0)
		nb := XskRingProdReserve(&tx, uint32(NumFrames/2), &pos)
		for i := uint32(0); i < nb; i++ {
			XskRingProdTxDesc(&tx, pos+i).Addr = uint64(i * uint32(FrameSize))
			XskRingProdTxDesc(&tx, pos+i).Len = uint32(60)
		}
		XskRingProdSubmit(&tx, nb)

		nb = XskRingProdReserve(&fill, uint32(NumFrames/2), &pos)
		for i := uint32(0); i < nb; i++ {
			*XskRingProdFillAddr(&fill, pos+i) = uint64((i + uint32(NumFrames/2)) * uint32(FrameSize))
		}
		XskRingProdSubmit(&fill, nb)

		unix.Poll([]unix.PollFd{{
			Fd:     int32(socket.Fd),
			Events: unix.POLLIN,
		}}, 0)
		go func() {
			now := time.Now()
			for {
				if time.Since(now) > 100000*time.Second {
					break
				}
				nPkts := XskRingConsPeek(&rx, uint32(NumFrames/2), &pos)
				var descList []unix.XDPDesc
				for i := uint32(0); i < nPkts; i++ {
					descList = append(descList, *XskRingConsRxDesc(&rx, pos+i))
				}
				XskRingConsRelease(&rx, nPkts)
				for _, desc := range descList {
					HexDump(umemArea[desc.Addr : desc.Addr+uint64(desc.Len)])
				}
				nb := XskRingProdReserve(&fill, nPkts, &pos)
				for i := uint32(0); i < nb; i++ {
					*XskRingProdFillAddr(&fill, pos+i) = descList[i].Addr
				}
				XskRingProdSubmit(&fill, nb)
				unix.Poll([]unix.PollFd{{
					Fd:     int32(socket.Fd),
					Events: unix.POLLIN,
				}}, 0)
			}
		}()
	}
	time.Sleep(100000 * time.Second)

}

func TestXskProgRel(t *testing.T) {
	iface := "ens1"
	NumFrames := 2048
	FrameSize := 4096

	ethChan, err := GetEthChannels(iface)
	if err != nil {
		log.Fatal("get queue error:", err)
	}
	socketList := []*XskSocket{}
	for queueID := 0; queueID < int(ethChan.TXCount); queueID++ {
		log.Println("正在初始化：", queueID)
		umemArea, err := unix.Mmap(-1, 0, NumFrames*FrameSize,
			unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE)
		if err != nil {
			log.Fatal("mmap error:", err)
		}
		log.Println(unsafe.Pointer(&umemArea[0]))
		defer unix.Munmap(umemArea)
		fill := XskRingProd{}
		comp := XskRingCons{}
		umem, err := XskUmemCreate(unsafe.Pointer(&umemArea[0]), uint64(NumFrames*FrameSize), &fill, &comp, &XskUmemConfig{
			FillSize:      uint32(NumFrames / 2),
			CompSize:      uint32(NumFrames / 2),
			FrameSize:     uint32(FrameSize),
			FrameHeadroom: uint32(0),
			Flags:         uint32(0),
		})
		log.Println(umem.UmemArea)
		if err != nil {
			log.Fatal("umem create error", err)
		}
		defer XskUmemDelete(umem)
		rx := XskRingCons{}
		tx := XskRingProd{}
		socket, err := XskSocketCreate(iface, uint32(queueID), umem, &rx, &tx, &XskSocketConfig{
			RxSize:      uint32(NumFrames / 2),
			TxSize:      uint32(NumFrames / 2),
			XdpFlags:    link.XDPGenericMode,
			BindFlags:   unix.XDP_USE_NEED_WAKEUP,
			LibbpfFlags: 0,
		})
		log.Println(socket.Ctx.Umem.UmemArea)
		if err != nil {
			log.Fatal("socket create error", err)
		}
		socketList = append(socketList, socket)
		pos := uint32(0)
		nb := XskRingProdReserve(&tx, uint32(NumFrames/2), &pos)
		for i := uint32(0); i < nb; i++ {
			XskRingProdTxDesc(&tx, pos+i).Addr = uint64(i * uint32(FrameSize))
			XskRingProdTxDesc(&tx, pos+i).Len = uint32(60)
		}
		XskRingProdSubmit(&tx, nb)

		nb = XskRingProdReserve(&fill, uint32(NumFrames/2), &pos)
		for i := uint32(0); i < nb; i++ {
			*XskRingProdFillAddr(&fill, pos+i) = uint64((i + uint32(NumFrames/2)) * uint32(FrameSize))
		}
		XskRingProdSubmit(&fill, nb)

		unix.Poll([]unix.PollFd{{
			Fd:     int32(socket.Fd),
			Events: unix.POLLIN,
		}}, 0)
	}
	for _, socket := range socketList {
		XskSocketDelete(socket)
	}

	time.Sleep(100000 * time.Second)

}
