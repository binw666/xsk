package xsk

import (
	"fmt"
	"unicode"
	"unsafe"

	"golang.org/x/sys/unix"
)

// xskPageAligned 检查给定的缓冲区指针是否是页面对齐的。
// 参数：
//   - buffer - 一个指向缓冲区的 unsafe.Pointer。
//
// 返回值：
//   - 如果缓冲区地址是页面对齐的，则返回 true；否则返回 false。
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

// GetEthChannels 获取给定网络接口的以太网通道配置。
// 它使用 ETHTOOL_GCHANNELS 命令通过 ioctl 系统调用获取通道信息。
//
// 参数:
//   - ifName: 网络接口的名称。
//
// 返回值:
//   - *EthtoolChannels: 一个指向 EthtoolChannels 结构体的指针，包含通道信息。
//   - error: 如果在过程中发生任何错误，则返回一个错误对象。
//
// 错误:
//   - 如果打开套接字时出现问题，则返回错误。
//   - 如果执行 ioctl 系统调用时出现问题，则返回错误。
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
		return nil, fmt.Errorf("打开套接字出错: %v", err)
	}
	defer unix.Close(fd)

	// 执行 ioctl 调用
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCETHTOOL), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return nil, fmt.Errorf("执行 ioctl 出错: %v", errno)
	}

	return &channels, nil
}

// HexDump 返回一个字符串，该字符串表示给定字节切片的十六进制视图。
// 输出的每一行包含 16 个字节的十六进制表示，后跟它们的 ASCII 表示。
// 不可打印的 ASCII 字符用点 ('.') 表示。
//
// 参数:
//   - data: 要转换为十六进制转储的字节切片。
//
// 返回值:
//
//	包含输入字节切片的十六进制转储的字符串。
func HexDump(data []byte) string {
	const bytesPerLine = 16
	var result string

	for i := 0; i < len(data); i += bytesPerLine {
		end := i + bytesPerLine
		if end > len(data) {
			end = len(data)
		}

		// Append hex bytes
		for j := i; j < end; j++ {
			result += fmt.Sprintf("%02X ", data[j])
		}

		// Pad remaining space if line is less than 16 bytes
		for j := end; j < i+bytesPerLine; j++ {
			result += "   "
		}

		// Append ASCII characters
		result += " | "
		for j := i; j < end; j++ {
			if unicode.IsPrint(rune(data[j])) {
				result += fmt.Sprintf("%c", data[j])
			} else {
				result += "."
			}
		}
		result += "\n"
	}

	return result
}
