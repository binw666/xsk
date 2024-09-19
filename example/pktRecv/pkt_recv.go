package main

import (
	"log"
	"time"
	"unsafe"

	"github.com/binw666/xsk"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func main() {
	iface := "ens1"
	NumFrames := 2048
	FrameSize := 4096

	ethChan, err := xsk.GetEthChannels(iface)
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
		fill := xsk.XskRingProd{}
		comp := xsk.XskRingCons{}
		umem, err := xsk.XskUmemCreate(unsafe.Pointer(&umemArea[0]), uint64(NumFrames*FrameSize), &fill, &comp, &xsk.XskUmemConfig{
			FillSize:      uint32(NumFrames / 2),
			CompSize:      uint32(NumFrames / 2),
			FrameSize:     uint32(FrameSize),
			FrameHeadroom: uint32(0),
			Flags:         uint32(0),
		})
		if err != nil {
			log.Fatal("umem create error", err)
		}
		defer xsk.XskUmemDelete(umem)
		rx := xsk.XskRingCons{}
		tx := xsk.XskRingProd{}
		socket, err := xsk.XskSocketCreate(iface, uint32(queueID), umem, &rx, &tx, &xsk.XskSocketConfig{
			RxSize:      uint32(NumFrames / 2),
			TxSize:      uint32(NumFrames / 2),
			XdpFlags:    link.XDPGenericMode,
			BindFlags:   unix.XDP_USE_NEED_WAKEUP,
			LibbpfFlags: 0,
		})
		if err != nil {
			log.Fatal("socket create error", err)
		}
		defer xsk.XskSocketDelete(socket)
		pos := uint32(0)
		nb := xsk.XskRingProdReserve(&tx, uint32(NumFrames/2), &pos)
		for i := uint32(0); i < nb; i++ {
			xsk.XskRingProdTxDesc(&tx, pos+i).Addr = uint64(i * uint32(FrameSize))
			xsk.XskRingProdTxDesc(&tx, pos+i).Len = uint32(60)
		}
		xsk.XskRingProdSubmit(&tx, nb)

		nb = xsk.XskRingProdReserve(&fill, uint32(NumFrames/2), &pos)
		for i := uint32(0); i < nb; i++ {
			*xsk.XskRingProdFillAddr(&fill, pos+i) = uint64((i + uint32(NumFrames/2)) * uint32(FrameSize))
		}
		xsk.XskRingProdSubmit(&fill, nb)

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
				nPkts := xsk.XskRingConsPeek(&rx, uint32(NumFrames/2), &pos)
				var descList []unix.XDPDesc
				for i := uint32(0); i < nPkts; i++ {
					descList = append(descList, *xsk.XskRingConsRxDesc(&rx, pos+i))
				}
				xsk.XskRingConsRelease(&rx, nPkts)
				for _, desc := range descList {
					xsk.HexDump(umemArea[desc.Addr : desc.Addr+uint64(desc.Len)])
				}
				nb := xsk.XskRingProdReserve(&fill, nPkts, &pos)
				for i := uint32(0); i < nb; i++ {
					*xsk.XskRingProdFillAddr(&fill, pos+i) = descList[i].Addr
				}
				xsk.XskRingProdSubmit(&fill, nb)
				unix.Poll([]unix.PollFd{{
					Fd:     int32(socket.Fd),
					Events: unix.POLLIN,
				}}, 0)
			}
		}()
	}
	time.Sleep(100000 * time.Second)

}
