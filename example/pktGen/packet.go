package main

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type EthernetConfig struct {
	SrcMAC []string `yaml:"src_mac"`
	DstMAC []string `yaml:"dst_mac"`
}

type IPConfig struct {
	TTL   []string `yaml:"ttl"`    // 支持单个值和范围
	SrcIP []string `yaml:"src_ip"` // 支持单个 IP 和 IP 范围
	DstIP []string `yaml:"dst_ip"` // 支持单个 IP 和 IP 范围
}

type TransportConfig struct {
	Protocol  string         `yaml:"protocol"`
	SrcPort   []string       `yaml:"src_port"`
	DstPort   []string       `yaml:"dst_port"`
	ICMPTypes []ICMPTypeCode `yaml:"icmp_types"` // 仅适用于 ICMP
}

type ICMPTypeCode struct {
	Type int `yaml:"type"`
	Code int `yaml:"code"`
}

// Utility Structures and Functions

// Range represents a numeric range with min and max
type Range struct {
	Min int
	Max int
}

func parseRangeString(s string) (Range, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Range{}, fmt.Errorf("empty range string")
	}

	if strings.Contains(s, "-") {
		parts := strings.Split(s, "-")
		if len(parts) != 2 {
			return Range{}, fmt.Errorf("invalid range format: %s", s)
		}
		min, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return Range{}, fmt.Errorf("invalid range min value: %s", parts[0])
		}
		max, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return Range{}, fmt.Errorf("invalid range max value: %s", parts[1])
		}
		if min > max {
			return Range{}, fmt.Errorf("range min (%d) greater than max (%d)", min, max)
		}
		return Range{Min: min, Max: max}, nil
	}

	val, err := strconv.Atoi(s)
	if err != nil {
		return Range{}, fmt.Errorf("invalid value: %s", s)
	}
	return Range{Min: val, Max: val}, nil
}

// parseMACList 解析 MAC 地址列表
func parseMACList(macList []string) ([]net.HardwareAddr, error) {
	var macs []net.HardwareAddr
	for _, macStr := range macList {
		mac, err := net.ParseMAC(macStr)
		if err != nil {
			return nil, fmt.Errorf("invalid MAC address %s: %v", macStr, err)
		}
		macs = append(macs, mac)
	}
	return macs, nil
}

// parseIPList 解析 IP 地址列表，支持单个 IP 和 IP 范围
func parseIPList(ipList []string) ([][2]net.IP, error) {
	var parsedIPs [][2]net.IP
	for _, ipStr := range ipList {
		if strings.Contains(ipStr, "-") {
			parts := strings.Split(ipStr, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid IP range: %s", ipStr)
			}
			minIP := net.ParseIP(strings.TrimSpace(parts[0])).To4()
			maxIP := net.ParseIP(strings.TrimSpace(parts[1])).To4()
			if minIP == nil || maxIP == nil {
				return nil, fmt.Errorf("invalid IP in range: %s", ipStr)
			}
			parsedIPs = append(parsedIPs, [2]net.IP{minIP, maxIP})
		} else {
			ip := net.ParseIP(ipStr).To4()
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address: %s", ipStr)
			}
			parsedIPs = append(parsedIPs, [2]net.IP{ip, ip})
		}
	}
	return parsedIPs, nil
}

func randomIP(ipRanges [][2]net.IP) net.IP {
	if len(ipRanges) == 0 {
		return net.IPv4(127, 0, 0, 1) // Return localhost if no ranges provided
	}

	selectedRange := ipRanges[rand.Intn(len(ipRanges))]
	minIP := selectedRange[0].To4()
	maxIP := selectedRange[1].To4()

	if minIP == nil || maxIP == nil {
		return net.IPv4(127, 0, 0, 1) // Return localhost if invalid IP
	}

	ip := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		if minIP[i] == maxIP[i] {
			ip[i] = minIP[i]
		} else {
			ip[i] = byte(rand.Intn(int(maxIP[i]-minIP[i])+1) + int(minIP[i]))
		}
	}
	return ip
}

// parseTTLList 解析 TTL 列表，支持单个值和范围
func parseTTLList(ttlList []string) ([]Range, error) {
	var ttlRanges []Range
	for _, ttlStr := range ttlList {
		ttlRange, err := parseRangeString(ttlStr)
		if err != nil {
			return nil, fmt.Errorf("invalid TTL entry '%s': %v", ttlStr, err)
		}
		// Ensure TTL is within valid range (1-255)
		if ttlRange.Min < 1 || ttlRange.Max > 255 {
			return nil, fmt.Errorf("TTL range %d-%d out of valid range (1-255)", ttlRange.Min, ttlRange.Max)
		}
		ttlRanges = append(ttlRanges, ttlRange)
	}
	return ttlRanges, nil
}

// randomTTL 在给定的 TTL 范围内随机生成一个 TTL
func randomTTL(ttlRanges []Range) uint8 {
	selectedRange := ttlRanges[rand.Intn(len(ttlRanges))]
	if selectedRange.Min == selectedRange.Max {
		return uint8(selectedRange.Min)
	}
	return uint8(rand.Intn(selectedRange.Max-selectedRange.Min+1) + selectedRange.Min)
}

// parsePortList 解析端口列表，支持单个端口和端口范围
func parsePortList(portList []string) ([]Range, error) {
	var portRanges []Range
	for _, portStr := range portList {
		portRange, err := parseRangeString(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port entry '%s': %v", portStr, err)
		}
		// Ensure port is within valid range (1-65535)
		if portRange.Min < 1 || portRange.Max > 65535 {
			return nil, fmt.Errorf("port range %d-%d out of valid range (1-65535)", portRange.Min, portRange.Max)
		}
		portRanges = append(portRanges, portRange)
	}
	return portRanges, nil
}

// randomPort 在给定的端口范围内随机生成一个端口
func randomPort(portRanges []Range) uint16 {
	selectedRange := portRanges[rand.Intn(len(portRanges))]
	if selectedRange.Min == selectedRange.Max {
		return uint16(selectedRange.Min)
	}
	return uint16(rand.Intn(selectedRange.Max-selectedRange.Min+1) + selectedRange.Min)
}

// randomICMPTypeCode 从 ICMP 类型列表中随机选择一个 (Type, Code) 组合
func randomICMPTypeCode(icmpTypes []ICMPTypeCode) (layers.ICMPv4TypeCode, error) {
	if len(icmpTypes) == 0 {
		return 0, errors.New("no ICMP types provided")
	}
	selected := icmpTypes[rand.Intn(len(icmpTypes))]
	return layers.CreateICMPv4TypeCode(uint8(selected.Type), uint8(selected.Code)), nil
}

func headerLengthForProtocol(protocol string) (int, error) {
	const (
		ethHeaderLen  = 14
		ipHeaderLen   = 20
		tcpHeaderLen  = 20
		udpHeaderLen  = 8
		icmpHeaderLen = 8
	)

	switch strings.ToUpper(protocol) {
	case "TCP":
		return ethHeaderLen + ipHeaderLen + tcpHeaderLen, nil
	case "UDP":
		return ethHeaderLen + ipHeaderLen + udpHeaderLen, nil
	case "ICMP":
		return ethHeaderLen + ipHeaderLen + icmpHeaderLen, nil
	default:
		return 0, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

type BuiltPacket struct {
	Bytes         []byte
	PayloadOffset int
	// SendNsOffset is the absolute byte offset of the 8-byte sendNs field inside Bytes.
	// -1 means timestamp header not present.
	SendNsOffset int
}

func BuildPacket(flow FlowConfig, payload PayloadSpec) (BuiltPacket, error) {
	// Validate minimum packet size
	headerLen, err := headerLengthForProtocol(flow.Transport.Protocol)
	if err != nil {
		return BuiltPacket{}, err
	}

	if flow.TotalSize < headerLen {
		return BuiltPacket{}, fmt.Errorf("total size %d is too small (minimum required: %d)",
			flow.TotalSize, headerLen)
	}

	// Validate protocol
	protocol := strings.ToUpper(flow.Transport.Protocol)
	if protocol != "TCP" && protocol != "UDP" && protocol != "ICMP" {
		return BuiltPacket{}, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	// Set default TTL if not provided
	if len(flow.IP.TTL) == 0 {
		flow.IP.TTL = []string{"64"}
	}

	// Parse configurations with proper error handling
	srcMACs, err := parseMACList(flow.Ethernet.SrcMAC)
	if err != nil {
		return BuiltPacket{}, fmt.Errorf("src MAC error: %v", err)
	}

	dstMACs, err := parseMACList(flow.Ethernet.DstMAC)
	if err != nil {
		return BuiltPacket{}, fmt.Errorf("dst MAC error: %v", err)
	}

	srcIPRanges, err := parseIPList(flow.IP.SrcIP)
	if err != nil {
		return BuiltPacket{}, fmt.Errorf("src IP error: %v", err)
	}

	dstIPRanges, err := parseIPList(flow.IP.DstIP)
	if err != nil {
		return BuiltPacket{}, fmt.Errorf("dst IP error: %v", err)
	}

	ttlRanges, err := parseTTLList(flow.IP.TTL)
	if err != nil {
		return BuiltPacket{}, fmt.Errorf("TTL error: %v", err)
	}

	// Create and serialize packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Create layers
	eth := &layers.Ethernet{
		SrcMAC:       selectMAC(srcMACs),
		DstMAC:       selectMAC(dstMACs),
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      randomTTL(ttlRanges),
		Protocol: getIPProtocol(protocol),
		SrcIP:    randomIP(srcIPRanges),
		DstIP:    randomIP(dstIPRanges),
	}

	// Create transport layer
	transport, err := createTransportLayer(protocol, flow, ip)
	if err != nil {
		return BuiltPacket{}, err
	}

	// Create payload
	payloadLen := flow.TotalSize - headerLen
	payloadBytes := createPayload(payloadLen, payload.Random)

	// Serialize all layers
	serialLayers := []gopacket.SerializableLayer{eth, ip, transport, gopacket.Payload(payloadBytes)}
	if err := gopacket.SerializeLayers(buffer, opts, serialLayers...); err != nil {
		return BuiltPacket{}, fmt.Errorf("serialization error: %v", err)
	}

	pkt := buffer.Bytes()
	payloadOffset := headerLen
	sendNsOffset := -1
	if payload.TimeStamp.Enable {
		if payloadLen < payload.TimeStamp.Offset+tsHeaderLen {
			return BuiltPacket{}, fmt.Errorf("timestamp enabled but payload too small: need >= %d bytes, got %d",
				payload.TimeStamp.Offset+tsHeaderLen, payloadLen)
		}
		if off, ok := writeTimestampHeader(pkt, payloadOffset, payload.TimeStamp); ok {
			sendNsOffset = off
		} else {
			return BuiltPacket{}, fmt.Errorf("failed to write timestamp header (payloadOffset=%d)", payloadOffset)
		}
	}
	return BuiltPacket{Bytes: pkt, PayloadOffset: payloadOffset, SendNsOffset: sendNsOffset}, nil
}

// Helper functions

func selectMAC(macs []net.HardwareAddr) net.HardwareAddr {
	if len(macs) == 0 {
		return net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	}
	return macs[rand.Intn(len(macs))]
}

func getIPProtocol(protocol string) layers.IPProtocol {
	switch protocol {
	case "TCP":
		return layers.IPProtocolTCP
	case "UDP":
		return layers.IPProtocolUDP
	case "ICMP":
		return layers.IPProtocolICMPv4
	default:
		return layers.IPProtocolICMPv4
	}
}

func createTransportLayer(protocol string, flow FlowConfig, ip *layers.IPv4) (gopacket.SerializableLayer, error) {
	var err error
	switch protocol {
	case "TCP":
		var srcPortRanges, dstPortRanges []Range
		if strings.ToUpper(flow.Transport.Protocol) == "TCP" || strings.ToUpper(flow.Transport.Protocol) == "UDP" {
			srcPortRanges, err = parsePortList(flow.Transport.SrcPort)
			if err != nil {
				return nil, fmt.Errorf("error parsing src_port: %v", err)
			}
			dstPortRanges, err = parsePortList(flow.Transport.DstPort)
			if err != nil {
				return nil, fmt.Errorf("error parsing dst_port: %v", err)
			}
		}
		if len(srcPortRanges) == 0 || len(dstPortRanges) == 0 {
			return nil, errors.New("TCP protocol requires src_port and dst_port configurations")
		}
		srcPort := randomPort(srcPortRanges)
		dstPort := randomPort(dstPortRanges)
		tcp := layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
			Seq:     rand.Uint32(),
			SYN:     true,
			Window:  65535,
		}
		tcp.SetNetworkLayerForChecksum(ip)
		return &tcp, nil
	case "UDP":
		var srcPortRanges, dstPortRanges []Range
		if strings.ToUpper(flow.Transport.Protocol) == "TCP" || strings.ToUpper(flow.Transport.Protocol) == "UDP" {
			srcPortRanges, err = parsePortList(flow.Transport.SrcPort)
			if err != nil {
				return nil, fmt.Errorf("error parsing src_port: %v", err)
			}
			dstPortRanges, err = parsePortList(flow.Transport.DstPort)
			if err != nil {
				return nil, fmt.Errorf("error parsing dst_port: %v", err)
			}
		}
		if len(srcPortRanges) == 0 || len(dstPortRanges) == 0 {
			return nil, errors.New("UDP protocol requires src_port and dst_port configurations")
		}
		srcPort := randomPort(srcPortRanges)
		dstPort := randomPort(dstPortRanges)
		udp := layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		udp.SetNetworkLayerForChecksum(ip)
		return &udp, nil
	case "ICMP":
		if len(flow.Transport.ICMPTypes) == 0 {
			return nil, errors.New("ICMP protocol requires icmp_types configurations")
		}
		icmpTypeCode, err := randomICMPTypeCode(flow.Transport.ICMPTypes)
		if err != nil {
			return nil, fmt.Errorf("error selecting ICMP type/code: %v", err)
		}
		icmp := layers.ICMPv4{
			TypeCode: icmpTypeCode,
			Id:       1,
			Seq:      1,
		}
		return &icmp, nil
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

func createPayload(length int, random bool) []byte {
	payload := make([]byte, length)
	if random {
		rand.Read(payload)
	} else {
		for i := range payload {
			payload[i] = 'a'
		}
	}
	return payload
}
