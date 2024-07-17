package xsk

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

func xskPageAligned(buffer unsafe.Pointer) bool {
	addr := uintptr(buffer)
	pageSize := uintptr(unix.Getpagesize())
	return (addr & (pageSize - 1)) == 0
}
