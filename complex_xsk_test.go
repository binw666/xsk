package xsk

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

func GenerateEthernetPacket(protocol string, totalLength int) ([]byte, error) {
	const (
		ethHeaderLen    = 14
		ipHeaderLen     = 20
		tcpHeaderLen    = 20
		udpHeaderLen    = 8
		icmpHeaderLen   = 8
		minTCPTotalLen  = ethHeaderLen + ipHeaderLen + tcpHeaderLen
		minUDPTotalLen  = ethHeaderLen + ipHeaderLen + udpHeaderLen
		minICMPTotalLen = ethHeaderLen + ipHeaderLen + icmpHeaderLen
	)

	var transportHeaderLen int
	switch protocol {
	case "TCP":
		transportHeaderLen = tcpHeaderLen
	case "UDP":
		transportHeaderLen = udpHeaderLen
	case "ICMP":
		transportHeaderLen = icmpHeaderLen
	default:
		return nil, errors.New("unsupported protocol")
	}

	// 计算负载长度
	payloadLen := totalLength - ethHeaderLen - ipHeaderLen - transportHeaderLen
	if payloadLen < 0 {
		return nil, fmt.Errorf("total length %d is too small for protocol %s", totalLength, protocol)
	}

	// 创建以太网层
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x0C, 0x29, 0x3E, 0x1A, 0x2B},
		DstMAC:       net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// 创建IP层
	ip := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: 0, // 根据协议设置
		SrcIP:    net.IP{192, 168, 1, 100},
		DstIP:    net.IP{192, 168, 1, 1},
	}

	// 创建传输层和相应的校验和
	var transportLayer gopacket.SerializableLayer
	switch protocol {
	case "TCP":
		ip.Protocol = layers.IPProtocolTCP
		tcp := layers.TCP{
			SrcPort: layers.TCPPort(12345),
			DstPort: layers.TCPPort(80),
			Seq:     0,
			SYN:     true,
			Window:  65535,
		}
		tcp.SetNetworkLayerForChecksum(&ip)
		transportLayer = &tcp
	case "UDP":
		ip.Protocol = layers.IPProtocolUDP
		udp := layers.UDP{
			SrcPort: layers.UDPPort(12345),
			DstPort: layers.UDPPort(53),
		}
		udp.SetNetworkLayerForChecksum(&ip)
		transportLayer = &udp
	case "ICMP":
		ip.Protocol = layers.IPProtocolICMPv4
		icmp := layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			Id:       1,
			Seq:      1,
		}
		transportLayer = &icmp
	}

	// 创建负载
	payload := make([]byte, payloadLen)
	for i := 0; i < payloadLen; i++ {
		payload[i] = 0x61 // 'a'
	}

	// 创建序列化缓冲区
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true, // 自动修正长度字段
		ComputeChecksums: true, // 自动计算校验和
	}

	// 序列化各层
	layersList := []gopacket.SerializableLayer{&eth, &ip, transportLayer, gopacket.Payload(payload)}
	err := gopacket.SerializeLayers(buffer, opts, layersList...)
	if err != nil {
		return nil, err
	}

	packetData := buffer.Bytes()

	// 检查生成的数据包长度是否符合要求
	if len(packetData) != totalLength {
		return nil, fmt.Errorf("generated packet length %d does not match the specified total length %d", len(packetData), totalLength)
	}

	return packetData, nil
}
func TestComplexXskSend(t *testing.T) {
	ifaceName := "ens2"
	pktSize := 64
	queueID := uint32(0)
	sendCount := uint64(0)
	complexXsk, descs, err := NewComplexXsk(ifaceName, queueID, &ComplexXskConfig{
		UmemConfig: &ComplexUmemConfig{
			FillSize:      2048,
			CompSize:      2048,
			FrameNum:      4096,
			FrameSize:     2048,
			FrameHeadroom: 0,
			Flags:         0,
		},
		SocketConfig: &ComplexSocketConfig{
			RxSize:      2048,
			TxSize:      2048,
			LibbpfFlags: XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
			XdpFlags:    link.XDPGenericMode,
			BindFlags:   unix.XDP_USE_NEED_WAKEUP,
		},
	})
	if err != nil {
		t.Fatalf("NewComplexXsk failed: %v", err)
	}
	defer complexXsk.Close()
	txDesc := make([]XDPDesc, 2048)
	for i := 0; i < 2048; i++ {
		txDesc[i] = descs[i]
	}
	rxDesc := make([]XDPDesc, 2048)
	for i := 0; i < 2048; i++ {
		rxDesc[i] = descs[i+2048]
	}
	for i := 0; i < 2048; i++ {
		txDesc[i].Len = uint32(pktSize)
		pkt, err := GenerateEthernetPacket("UDP", pktSize)
		if err != nil {
			t.Fatalf("GenerateEthernetPacket failed: %v", err)
		}
		copy(complexXsk.UmemArea(txDesc[i]), pkt)
	}
	complexXsk.PopulateTxRing(txDesc)
	go func() {
		for {
			time.Sleep(1 * time.Second)
			sendCount := atomic.SwapUint64(&sendCount, 0)
			fmt.Printf("Send %d packets, %d bytes\n", sendCount, sendCount*uint64(pktSize))
		}
	}()
	for {
		complexXsk.Poll(unix.POLLOUT, -1)
		recyDescs := complexXsk.RecycleCompRing()
		atomic.AddUint64(&sendCount, uint64(len(recyDescs)))
		for i := 0; i < len(recyDescs); i++ {
			recyDescs[i].Len = uint32(pktSize)
		}
		complexXsk.PopulateTxRing(recyDescs)
	}
}

func TestComplexXskRecv(t *testing.T) {
	ifaceName := "ens2"
	queueID := uint32(0)
	recvCount := uint64(0)
	recvBytes := uint64(0)
	complexXsk, descs, err := NewComplexXsk(ifaceName, queueID, &ComplexXskConfig{
		UmemConfig: &ComplexUmemConfig{
			FillSize:      2048,
			CompSize:      2048,
			FrameNum:      4096,
			FrameSize:     2048,
			FrameHeadroom: 0,
			Flags:         0,
		},
		SocketConfig: &ComplexSocketConfig{
			RxSize:      2048,
			TxSize:      2048,
			LibbpfFlags: 0,
			XdpFlags:    link.XDPGenericMode,
			BindFlags:   unix.XDP_USE_NEED_WAKEUP,
		},
	})
	if err != nil {
		t.Fatalf("NewComplexXsk failed: %v", err)
	}
	defer complexXsk.Close()
	txDesc := make([]XDPDesc, 2048)
	for i := 0; i < 2048; i++ {
		txDesc[i] = descs[i]
	}
	rxDesc := make([]XDPDesc, 2048)
	for i := 0; i < 2048; i++ {
		rxDesc[i] = descs[i+2048]
	}
	complexXsk.PopulateFillRing(rxDesc)
	go func() {
		for {
			time.Sleep(1 * time.Second)
			recvCount := atomic.SwapUint64(&recvCount, 0)
			recvBytes := atomic.SwapUint64(&recvBytes, 0)
			fmt.Printf("Received %d packets, %d bytes\n", recvCount, recvBytes)
		}
	}()
	for {
		complexXsk.Poll(unix.POLLIN, -1)
		recyDescs := complexXsk.RecycleRxRing()
		atomic.AddUint64(&recvCount, uint64(len(recyDescs)))
		for i := 0; i < len(recyDescs); i++ {
			atomic.AddUint64(&recvBytes, uint64(recyDescs[i].Len))
		}
		complexXsk.PopulateFillRing(recyDescs)
	}
}

func TestComplexXsk(t *testing.T) {
	ifaceName := "ens2"
	queueID := uint32(0)
	complexXsk, descs, err := NewComplexXsk(ifaceName, queueID, &ComplexXskConfig{
		UmemConfig: &ComplexUmemConfig{
			FillSize:      2048,
			CompSize:      2048,
			FrameNum:      4096,
			FrameSize:     2048,
			FrameHeadroom: 0,
			Flags:         0,
		},
		SocketConfig: &ComplexSocketConfig{
			RxSize:      2048,
			TxSize:      2048,
			LibbpfFlags: 0,
			XdpFlags:    link.XDPGenericMode,
			BindFlags:   unix.XDP_USE_NEED_WAKEUP,
		},
	})
	if err != nil {
		t.Fatalf("NewComplexXsk failed: %v", err)
	}
	defer complexXsk.Close()
	txDesc := make([]XDPDesc, 2048)
	for i := 0; i < 2048; i++ {
		txDesc[i] = descs[i]
	}
	rxDesc := make([]XDPDesc, 2048)
	for i := 0; i < 2048; i++ {
		rxDesc[i] = descs[i+2048]
	}
}
