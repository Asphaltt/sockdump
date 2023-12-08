// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Leon Hwang.

package sockdump

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

// Very hacky way to check whether tracing link is supported.
func HaveBPFLinkTracing() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "fexit_skb_clone",
		Type: ebpf.Tracing,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachTraceFExit,
		AttachTo:   "skb_clone",
		License:    "MIT",
	})
	if err != nil {
		return false
	}
	defer prog.Close()

	link, err := link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
	if err != nil {
		return false
	}
	defer link.Close()

	return true
}
