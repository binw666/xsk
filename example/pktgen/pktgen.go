package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"time"
	"unsafe"

	"github.com/binw666/xsk"
	"golang.org/x/sys/unix"
)

func GetCurrentTXQueues(interfaceName string) (int, error) {
	cmd := exec.Command("ethtool", "-l", interfaceName)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return 0, err
	}

	// Adjusted regular expression to work across multiple lines
	rx := regexp.MustCompile(`(?s)Current hardware settings:.*?TX:\s+(\d+)`)
	matches := rx.FindStringSubmatch(out.String())
	if len(matches) < 2 {
		// If the TX queues are not found, try to find the combined queues
		rx = regexp.MustCompile(`(?s)Current hardware settings:.*?Combined:\s+(\d+)`)
		matches = rx.FindStringSubmatch(out.String())
		if len(matches) < 2 {
			fmt.Println("could not find TX queues in output")
			return 0, fmt.Errorf("could not find TX queues in output")
		}
	}
	var txQueues int
	fmt.Sscanf(matches[1], "%d", &txQueues)

	return txQueues, nil
}

func main() {
	iface := "ens1f0"
	// iface := "ens1"
	NumFrames := 2048
	FrameSize := 4096

	txQueues, err := GetCurrentTXQueues(iface)
	if err != nil {
		log.Fatal("get queue error:", err)
	}

	for queueID := 0; queueID < txQueues; queueID++ {
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
			XdpFlags:    uint32(0),
			BindFlags:   unix.XDP_USE_NEED_WAKEUP,
			LibbpfFlags: uint32(xsk.XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD),
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
		unix.Sendto(socket.Fd, nil, unix.MSG_DONTWAIT, nil)
		go func() {
			now := time.Now()
			for {
				if time.Since(now) > 10*time.Second {
					break
				}
				nPkts := xsk.XskRingConsPeek(&comp, uint32(NumFrames/2), &pos)
				var addrList []uint64
				for i := uint32(0); i < nPkts; i++ {
					addrList = append(addrList, *xsk.XskRingConsCompAddr(&comp, pos+i))
				}
				xsk.XskRingConsRelease(&comp, nPkts)
				nb := xsk.XskRingProdReserve(&tx, nPkts, &pos)
				for i := uint32(0); i < nb; i++ {
					xsk.XskRingProdTxDesc(&tx, pos+i).Addr = addrList[i]
					xsk.XskRingProdTxDesc(&tx, pos+i).Len = uint32(60)
				}
				xsk.XskRingProdSubmit(&tx, nb)
				unix.Sendto(socket.Fd, nil, unix.MSG_DONTWAIT, nil)
			}
		}()
	}
	time.Sleep(15 * time.Second)
}
