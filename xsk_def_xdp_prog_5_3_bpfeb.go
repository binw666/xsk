// Code generated by bpf2go; DO NOT EDIT.
//go:build mips || mips64 || ppc64 || s390x

package xsk

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadXsk_def_xdp_prog_5_3 returns the embedded CollectionSpec for xsk_def_xdp_prog_5_3.
func loadXsk_def_xdp_prog_5_3() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Xsk_def_xdp_prog_5_3Bytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load xsk_def_xdp_prog_5_3: %w", err)
	}

	return spec, err
}

// loadXsk_def_xdp_prog_5_3Objects loads xsk_def_xdp_prog_5_3 and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*xsk_def_xdp_prog_5_3Objects
//	*xsk_def_xdp_prog_5_3Programs
//	*xsk_def_xdp_prog_5_3Maps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadXsk_def_xdp_prog_5_3Objects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadXsk_def_xdp_prog_5_3()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// xsk_def_xdp_prog_5_3Specs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xsk_def_xdp_prog_5_3Specs struct {
	xsk_def_xdp_prog_5_3ProgramSpecs
	xsk_def_xdp_prog_5_3MapSpecs
}

// xsk_def_xdp_prog_5_3Specs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xsk_def_xdp_prog_5_3ProgramSpecs struct {
	XskDefProg *ebpf.ProgramSpec `ebpf:"xsk_def_prog"`
}

// xsk_def_xdp_prog_5_3MapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xsk_def_xdp_prog_5_3MapSpecs struct {
	XsksMap *ebpf.MapSpec `ebpf:"xsks_map"`
}

// xsk_def_xdp_prog_5_3Objects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadXsk_def_xdp_prog_5_3Objects or ebpf.CollectionSpec.LoadAndAssign.
type xsk_def_xdp_prog_5_3Objects struct {
	xsk_def_xdp_prog_5_3Programs
	xsk_def_xdp_prog_5_3Maps
}

func (o *xsk_def_xdp_prog_5_3Objects) Close() error {
	return _Xsk_def_xdp_prog_5_3Close(
		&o.xsk_def_xdp_prog_5_3Programs,
		&o.xsk_def_xdp_prog_5_3Maps,
	)
}

// xsk_def_xdp_prog_5_3Maps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadXsk_def_xdp_prog_5_3Objects or ebpf.CollectionSpec.LoadAndAssign.
type xsk_def_xdp_prog_5_3Maps struct {
	XsksMap *ebpf.Map `ebpf:"xsks_map"`
}

func (m *xsk_def_xdp_prog_5_3Maps) Close() error {
	return _Xsk_def_xdp_prog_5_3Close(
		m.XsksMap,
	)
}

// xsk_def_xdp_prog_5_3Programs contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadXsk_def_xdp_prog_5_3Objects or ebpf.CollectionSpec.LoadAndAssign.
type xsk_def_xdp_prog_5_3Programs struct {
	XskDefProg *ebpf.Program `ebpf:"xsk_def_prog"`
}

func (p *xsk_def_xdp_prog_5_3Programs) Close() error {
	return _Xsk_def_xdp_prog_5_3Close(
		p.XskDefProg,
	)
}

func _Xsk_def_xdp_prog_5_3Close(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed xsk_def_xdp_prog_5_3_bpfeb.o
var _Xsk_def_xdp_prog_5_3Bytes []byte
