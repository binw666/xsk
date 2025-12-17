package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type GeneratorConfig struct {
	TotalSize        int          `yaml:"total_size"`
	TemplatesPerFlow int          `yaml:"templates_per_flow"`
	Payload          PayloadSpec  `yaml:"payload"`
	Flows            []FlowConfig `yaml:"flows"`
}

type FlowConfig struct {
	Name      string          `yaml:"name"`
	Weight    int             `yaml:"weight"`
	TotalSize int             `yaml:"total_size"`
	Ethernet  EthernetConfig  `yaml:"ethernet"`
	IP        IPConfig        `yaml:"ip"`
	Transport TransportConfig `yaml:"transport"`
	Payload   *PayloadSpec    `yaml:"payload"`
}

type PayloadSpec struct {
	Random    bool            `yaml:"random"`
	TimeStamp TimestampConfig `yaml:"timestamp"`
}

func (p *PayloadSpec) applyDefaults() {
	// no-op for now
}

func (f *FlowConfig) applyDefaults() {
	if f.Weight <= 0 {
		f.Weight = 1
	}
}

func (c *GeneratorConfig) applyDefaults() {
	if c.TemplatesPerFlow <= 0 {
		c.TemplatesPerFlow = 512
	}
	c.Payload.applyDefaults()
	for i := range c.Flows {
		c.Flows[i].applyDefaults()
	}
}

func (c GeneratorConfig) normalize() (GeneratorConfig, error) {
	c.applyDefaults()
	if len(c.Flows) == 0 {
		return GeneratorConfig{}, fmt.Errorf("no flows configured (missing 'flows'?)")
	}

	for i := range c.Flows {
		if c.Flows[i].TotalSize == 0 {
			c.Flows[i].TotalSize = c.TotalSize
		}
		if c.Flows[i].TotalSize <= 0 {
			return GeneratorConfig{}, fmt.Errorf("flow[%d] total_size must be >0", i)
		}
		if strings.TrimSpace(c.Flows[i].Transport.Protocol) == "" {
			return GeneratorConfig{}, fmt.Errorf("flow[%d] transport.protocol is required", i)
		}
		if c.Flows[i].Payload == nil {
			base := c.Payload
			c.Flows[i].Payload = &base
		}
	}
	return c, nil
}

func LoadGeneratorConfig(path string) (GeneratorConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return GeneratorConfig{}, fmt.Errorf("read config: %w", err)
	}

	// First attempt: new schema.
	var cfg GeneratorConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return GeneratorConfig{}, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()

	if len(cfg.Flows) > 0 {
		for i := range cfg.Flows {
			if cfg.Flows[i].TotalSize == 0 {
				cfg.Flows[i].TotalSize = cfg.TotalSize
			}
		}
		return cfg.normalize()
	}

	// Fallback: legacy schema (single flow).
	var legacy legacyConfig
	if err := yaml.Unmarshal(b, &legacy); err != nil {
		return GeneratorConfig{}, fmt.Errorf("parse legacy config: %w", err)
	}
	return legacy.toGeneratorConfig()
}

// legacyConfig matches the previous example/pktGen schema for backwards compatibility.
type legacyConfig struct {
	TotalSize int             `yaml:"total_size"`
	Ethernet  EthernetConfig  `yaml:"ethernet"`
	IP        IPConfig        `yaml:"ip"`
	Transport TransportConfig `yaml:"transport"`
	Payload   struct {
		Random    bool `yaml:"random"`
		TimeStamp bool `yaml:"timestamp"`
	} `yaml:"payload"`
}

func (legacy legacyConfig) toGeneratorConfig() (GeneratorConfig, error) {
	cfg := GeneratorConfig{
		TotalSize: legacy.TotalSize,
		Payload: PayloadSpec{
			Random: legacy.Payload.Random,
			TimeStamp: TimestampConfig{
				Enable: legacy.Payload.TimeStamp,
			},
		},
		Flows: []FlowConfig{
			{
				Name:      "legacy",
				Weight:    1,
				TotalSize: legacy.TotalSize,
				Ethernet:  legacy.Ethernet,
				IP:        legacy.IP,
				Transport: legacy.Transport,
			},
		},
	}
	cfg.applyDefaults()
	base := cfg.Payload
	cfg.Flows[0].Payload = &base
	return cfg.normalize()
}
