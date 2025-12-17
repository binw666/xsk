package main

import (
	"encoding/binary"
	"fmt"

	"gopkg.in/yaml.v3"
)

const (
	tsMagicDefault = "XSKT"
	tsVersion      = uint16(1)
	tsHeaderLen    = 16 // magic(4) + ver(2) + flags(2) + sendNs(8)
)

type TimestampConfig struct {
	Enable bool   `yaml:"enable"`
	Offset int    `yaml:"offset"` // bytes into payload
	Magic  string `yaml:"magic"`
}

func (c *TimestampConfig) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		// Backwards compatible: "timestamp: true"
		var b bool
		if err := value.Decode(&b); err != nil {
			return err
		}
		c.Enable = b
		return nil
	case yaml.MappingNode:
		type ts TimestampConfig
		var tmp ts
		if err := value.Decode(&tmp); err != nil {
			return err
		}
		*c = TimestampConfig(tmp)
		return nil
	default:
		return fmt.Errorf("timestamp must be bool or map")
	}
}

func (c TimestampConfig) magicBytes() [4]byte {
	magic := c.Magic
	if magic == "" {
		magic = tsMagicDefault
	}
	var out [4]byte
	copy(out[:], []byte(magic))
	return out
}

func writeTimestampHeader(pkt []byte, payloadOffset int, cfg TimestampConfig) (sendNsOffset int, ok bool) {
	if !cfg.Enable {
		return 0, false
	}
	start := payloadOffset + cfg.Offset
	if start < 0 || start+tsHeaderLen > len(pkt) {
		return 0, false
	}
	magic := cfg.magicBytes()
	copy(pkt[start:start+4], magic[:])
	binary.LittleEndian.PutUint16(pkt[start+4:start+6], tsVersion)
	binary.LittleEndian.PutUint16(pkt[start+6:start+8], 0)
	// sendNs bytes [start+8 : start+16] set by fast path
	return start + 8, true
}
