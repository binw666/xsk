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

// Config 定义配置文件的结构
type Config struct {
	TotalSize int             `yaml:"total_size"`
	Ethernet  EthernetConfig  `yaml:"ethernet"`
	IP        IPConfig        `yaml:"ip"`
	Transport TransportConfig `yaml:"transport"`
	Payload   PayloadConfig   `yaml:"payload"`
}

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

type PayloadConfig struct {
	Random    bool `yaml:"random"`
	TimeStamp bool `yaml:"timestamp"`
}

// Utility Structures and Functions

// Range represents a numeric range with min and max
type Range struct {
	Min int
	Max int
}

// parseRangeString parses a string which can be a single number or a range "min-max"
func parseRangeString(s string) (Range, error) {
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
	// Single value
	val, err := strconv.Atoi(strings.TrimSpace(s))
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

// randomIP 在给定的 IP 范围内随机生成一个 IP
func randomIP(ipRanges [][2]net.IP) net.IP {
	selectedRange := ipRanges[rand.Intn(len(ipRanges))]
	minIP := selectedRange[0].To4()
	maxIP := selectedRange[1].To4()
	ip := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		if minIP[i] > maxIP[i] {
			ip[i] = minIP[i]
		} else if minIP[i] == maxIP[i] {
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

func GetAllHeaderLength(config Config) int {
	const (
		ethHeaderLen  = 14
		ipHeaderLen   = 20
		tcpHeaderLen  = 20
		udpHeaderLen  = 8
		icmpHeaderLen = 8
	)
	switch strings.ToUpper(config.Transport.Protocol) {
	case "TCP":
		return ethHeaderLen + ipHeaderLen + tcpHeaderLen
	case "UDP":
		return ethHeaderLen + ipHeaderLen + udpHeaderLen
	case "ICMP":
		return ethHeaderLen + ipHeaderLen + icmpHeaderLen
	default:
		return 0
	}
}

// GenerateEthernetPacket 根据配置生成以太网数据包
func GenerateEthernetPacket(config Config) ([]byte, error) {
	const (
		ethHeaderLen  = 14
		ipHeaderLen   = 20
		tcpHeaderLen  = 20
		udpHeaderLen  = 8
		icmpHeaderLen = 8
	)

	// Determine transport header length based on protocol
	var transportHeaderLen int
	switch strings.ToUpper(config.Transport.Protocol) {
	case "TCP":
		transportHeaderLen = tcpHeaderLen
	case "UDP":
		transportHeaderLen = udpHeaderLen
	case "ICMP":
		transportHeaderLen = icmpHeaderLen
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", config.Transport.Protocol)
	}

	// Calculate payload length
	payloadLen := config.TotalSize - ethHeaderLen - ipHeaderLen - transportHeaderLen
	if payloadLen < 0 {
		return nil, fmt.Errorf("total size %d is too small for protocol %s", config.TotalSize, config.Transport.Protocol)
	}

	// Parse Ethernet MAC addresses
	srcMACs, err := parseMACList(config.Ethernet.SrcMAC)
	if err != nil {
		return nil, err
	}
	if len(srcMACs) == 0 {
		// 使用默认源 MAC 地址
		srcMACs = append(srcMACs, net.HardwareAddr{0x00, 0x0C, 0x29, 0x3E, 0x1A, 0x2B})
	}

	dstMACs, err := parseMACList(config.Ethernet.DstMAC)
	if err != nil {
		return nil, err
	}
	if len(dstMACs) == 0 {
		// 使用默认目的 MAC 地址（广播地址）
		dstMACs = append(dstMACs, net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	}

	// Parse IP lists
	srcIPRanges, err := parseIPList(config.IP.SrcIP)
	if err != nil {
		return nil, fmt.Errorf("error parsing src_ip: %v", err)
	}
	dstIPRanges, err := parseIPList(config.IP.DstIP)
	if err != nil {
		return nil, fmt.Errorf("error parsing dst_ip: %v", err)
	}

	// Parse TTL list
	ttlRanges, err := parseTTLList(config.IP.TTL)
	if err != nil {
		return nil, fmt.Errorf("error parsing ttl: %v", err)
	}

	// Parse port lists if applicable
	var srcPortRanges, dstPortRanges []Range
	if strings.ToUpper(config.Transport.Protocol) == "TCP" || strings.ToUpper(config.Transport.Protocol) == "UDP" {
		srcPortRanges, err = parsePortList(config.Transport.SrcPort)
		if err != nil {
			return nil, fmt.Errorf("error parsing src_port: %v", err)
		}
		dstPortRanges, err = parsePortList(config.Transport.DstPort)
		if err != nil {
			return nil, fmt.Errorf("error parsing dst_port: %v", err)
		}
	}

	// Randomly select Ethernet MAC addresses
	srcMAC := srcMACs[rand.Intn(len(srcMACs))]
	dstMAC := dstMACs[rand.Intn(len(dstMACs))]

	// Randomly select IP addresses
	srcIP := randomIP(srcIPRanges)
	dstIP := randomIP(dstIPRanges)

	// Randomly select TTL
	ttl := randomTTL(ttlRanges)

	// Create Ethernet layer
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create IP layer
	ip := layers.IPv4{
		Version: 4,
		IHL:     5,
		TTL:     ttl,
		SrcIP:   srcIP,
		DstIP:   dstIP,
	}

	// Create Transport layer
	var transportLayer gopacket.SerializableLayer
	switch strings.ToUpper(config.Transport.Protocol) {
	case "TCP":
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
		tcp.SetNetworkLayerForChecksum(&ip)
		transportLayer = &tcp
	case "UDP":
		if len(srcPortRanges) == 0 || len(dstPortRanges) == 0 {
			return nil, errors.New("UDP protocol requires src_port and dst_port configurations")
		}
		srcPort := randomPort(srcPortRanges)
		dstPort := randomPort(dstPortRanges)
		udp := layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		udp.SetNetworkLayerForChecksum(&ip)
		transportLayer = &udp
	case "ICMP":
		if len(config.Transport.ICMPTypes) == 0 {
			return nil, errors.New("ICMP protocol requires icmp_types configurations")
		}
		icmpTypeCode, err := randomICMPTypeCode(config.Transport.ICMPTypes)
		if err != nil {
			return nil, fmt.Errorf("error selecting ICMP type/code: %v", err)
		}
		icmp := layers.ICMPv4{
			TypeCode: icmpTypeCode,
			Id:       1,
			Seq:      1,
		}
		transportLayer = &icmp
	}

	// Create payload
	var payload []byte
	if config.Payload.Random {
		payload = make([]byte, payloadLen)
		rand.Read(payload)
	} else {
		// 固定填充 'a' 字节
		payload = make([]byte, payloadLen)
		for i := range payload {
			payload[i] = 'a'
		}
	}

	// Create serialization buffer
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true, // 自动修正长度字段
		ComputeChecksums: true, // 自动计算校验和
	}

	// Assemble layers
	var layersList []gopacket.SerializableLayer
	layersList = append(layersList, &eth, &ip, transportLayer, gopacket.Payload(payload))

	// Serialize layers
	err = gopacket.SerializeLayers(buffer, opts, layersList...)
	if err != nil {
		return nil, fmt.Errorf("error serializing layers: %v", err)
	}

	packetData := buffer.Bytes()

	// Verify total length
	if len(packetData) != config.TotalSize {
		return nil, fmt.Errorf("generated packet length %d does not match the specified total size %d", len(packetData), config.TotalSize)
	}

	return packetData, nil
}
