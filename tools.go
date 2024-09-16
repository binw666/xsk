package xsk

import (
	"fmt"
	"unicode"
	"unsafe"

	"golang.org/x/sys/unix"
)

func xskPageAligned(buffer unsafe.Pointer) bool {
	addr := uintptr(buffer)
	pageSize := uintptr(unix.Getpagesize())
	return (addr & (pageSize - 1)) == 0
}

type EthtoolChannels struct {
	cmd           uint32
	MaxRX         uint32
	MaxTX         uint32
	MaxOther      uint32
	MaxCombined   uint32
	RXCount       uint32
	TXCount       uint32
	OtherCount    uint32
	CombinedCount uint32
}

type ifreqData struct {
	Name [unix.IFNAMSIZ]byte
	Data uintptr
	Pad  [16]byte // 填充到总大小为 40 字节
}

func GetEthChannels(ifName string) (*EthtoolChannels, error) {
	channels := EthtoolChannels{
		cmd: unix.ETHTOOL_GCHANNELS,
	}

	var ifr ifreqData
	copy(ifr.Name[:], ifName)
	ifr.Data = uintptr(unsafe.Pointer(&channels))

	// 打开套接字
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, fmt.Errorf("打开套接字出错: %v\n", err)
	}
	defer unix.Close(fd)

	// 执行 ioctl 调用
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCETHTOOL), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return nil, fmt.Errorf("执行 ioctl 出错: %v\n", errno)
	}

	return &channels, nil
}

// HexDump prints the bytes in hex format along with their ASCII representation
func HexDump(data []byte) {
	const bytesPerLine = 16
	for i := 0; i < len(data); i += bytesPerLine {
		end := i + bytesPerLine
		if end > len(data) {
			end = len(data)
		}

		// Print hex bytes
		for j := i; j < end; j++ {
			fmt.Printf("%02X ", data[j])
		}

		// Pad remaining space if line is less than 16 bytes
		for j := end; j < i+bytesPerLine; j++ {
			fmt.Print("   ")
		}

		// Print ASCII characters
		fmt.Print(" | ")
		for j := i; j < end; j++ {
			if unicode.IsPrint(rune(data[j])) {
				fmt.Printf("%c", data[j])
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println()
	}
}
