package xsk

import (
	"log"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestXskUmemCreate(t *testing.T) {
	NumFrames := 2048
	FrameSize := 4096
	umemArea, err := unix.Mmap(-1, 0, NumFrames*FrameSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE)
	if err != nil {
		log.Fatal("mmap error:", err)
	}
	defer unix.Munmap(umemArea)
	size := uint64(4096)
	fill := &XskRingProd{}
	comp := &XskRingCons{}
	usrConfig := &XskUmemConfig{
		FillSize:      2048,
		CompSize:      2048,
		FrameSize:     2048,
		FrameHeadroom: 0,
		Flags:         0,
	}

	umem, err := XskUmemCreate(unsafe.Pointer(&umemArea[0]), size, fill, comp, usrConfig)
	if err != nil {
		t.Fatalf("XskUmemCreate failed: %v", err)
	}

	if umem == nil {
		t.Fatalf("XskUmemCreate returned nil umem")
	}

	if umem.UmemArea != unsafe.Pointer(&umemArea[0]) {
		t.Errorf("Expected umemArea to be %v, got %v", umemArea, umem.UmemArea)
	}

	if umem.Config.FillSize != usrConfig.FillSize {
		t.Errorf("Expected FillSize to be %v, got %v", usrConfig.FillSize, umem.Config.FillSize)
	}

	if umem.Config.CompSize != usrConfig.CompSize {
		t.Errorf("Expected CompSize to be %v, got %v", usrConfig.CompSize, umem.Config.CompSize)
	}

	if umem.Config.FrameSize != usrConfig.FrameSize {
		t.Errorf("Expected FrameSize to be %v, got %v", usrConfig.FrameSize, umem.Config.FrameSize)
	}

	if umem.Config.FrameHeadroom != usrConfig.FrameHeadroom {
		t.Errorf("Expected FrameHeadroom to be %v, got %v", usrConfig.FrameHeadroom, umem.Config.FrameHeadroom)
	}

	if umem.Config.Flags != usrConfig.Flags {
		t.Errorf("Expected Flags to be %v, got %v", usrConfig.Flags, umem.Config.Flags)
	}

	if umem.FillSave == nil || umem.CompSave == nil {
		t.Fatalf("Expected FillSave and CompSave to be non-nil")
	}

	if umem.Fd <= 0 {
		t.Fatalf("Expected Fd to be > 0, got %d", umem.Fd)
	}

	if umem.Refcount != 0 {
		t.Fatalf("Expected Refcount to be 0, got %d", umem.Refcount)
	}

	if umem.CtxList == nil || umem.CtxList.Len() != 0 {
		t.Fatalf("Expected CtxList to be non-nil and empty")
	}

	if umem.RxRingSetupDone || umem.TxRingSetupDone {
		t.Fatalf("Expected RxRingSetupDone and TxRingSetupDone to be false")
	}

	err = XskUmemDelete(umem)
	if err != nil {
		t.Fatalf("XskUmemDelete failed: %v", err)
	}
}

func TestXskUmemCreateWithFd(t *testing.T) {

	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		t.Fatalf("unix.Socket failed: %v", err)
	}
	defer unix.Close(fd)

	NumFrames := 2048
	FrameSize := 4096
	umemArea, err := unix.Mmap(-1, 0, NumFrames*FrameSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE)
	if err != nil {
		log.Fatal("mmap error:", err)
	}
	defer unix.Munmap(umemArea)
	size := uint64(4096)
	fill := &XskRingProd{}
	comp := &XskRingCons{}
	usrConfig := &XskUmemConfig{
		FillSize:      2048,
		CompSize:      2048,
		FrameSize:     2048,
		FrameHeadroom: 0,
		Flags:         0,
	}

	umem, err := XskUmemCreate(unsafe.Pointer(&umemArea[0]), size, fill, comp, usrConfig)
	if err != nil {
		t.Fatalf("XskUmemCreate failed: %v", err)
	}

	if umem == nil {
		t.Fatalf("XskUmemCreate returned nil umem")
	}

	if umem.UmemArea != unsafe.Pointer(&umemArea[0]) {
		t.Errorf("Expected umemArea to be %v, got %v", umemArea, umem.UmemArea)
	}

	if umem.Config.FillSize != usrConfig.FillSize {
		t.Errorf("Expected FillSize to be %v, got %v", usrConfig.FillSize, umem.Config.FillSize)
	}

	if umem.Config.CompSize != usrConfig.CompSize {
		t.Errorf("Expected CompSize to be %v, got %v", usrConfig.CompSize, umem.Config.CompSize)
	}

	if umem.Config.FrameSize != usrConfig.FrameSize {
		t.Errorf("Expected FrameSize to be %v, got %v", usrConfig.FrameSize, umem.Config.FrameSize)
	}

	if umem.Config.FrameHeadroom != usrConfig.FrameHeadroom {
		t.Errorf("Expected FrameHeadroom to be %v, got %v", usrConfig.FrameHeadroom, umem.Config.FrameHeadroom)
	}

	if umem.Config.Flags != usrConfig.Flags {
		t.Errorf("Expected Flags to be %v, got %v", usrConfig.Flags, umem.Config.Flags)
	}

	if umem.FillSave == nil || umem.CompSave == nil {
		t.Fatalf("Expected FillSave and CompSave to be non-nil")
	}

	if umem.Fd <= 0 {
		t.Fatalf("Expected Fd to be > 0, got %d", umem.Fd)
	}

	if umem.Refcount != 0 {
		t.Fatalf("Expected Refcount to be 0, got %d", umem.Refcount)
	}

	if umem.CtxList == nil || umem.CtxList.Len() != 0 {
		t.Fatalf("Expected CtxList to be non-nil and empty")
	}

	if umem.RxRingSetupDone || umem.TxRingSetupDone {
		t.Fatalf("Expected RxRingSetupDone and TxRingSetupDone to be false")
	}

	err = XskUmemDelete(umem)
	if err != nil {
		t.Fatalf("XskUmemDelete failed: %v", err)
	}
}
