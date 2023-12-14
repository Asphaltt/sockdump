// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Leon Hwang.

package sockdump

import (
	flags "github.com/spf13/pflag"
)

type Flags struct {
	Pid          uint
	SegSize      uint
	SegsPerMsg   uint
	SegsInBuffer uint

	Format string

	Output string

	Sock string
}

func NewFlags() *Flags {
	var f Flags

	flags.UintVar(&f.Pid, "pid", 0, "pid of the process to trace")
	flags.UintVar(&f.SegSize, "seg-size", 1024*50, "max segment size, increase this number if packet size is longer than captured size")
	flags.UintVar(&f.SegsPerMsg, "segs-per-msg", 10, "max number of iovec segments")
	flags.UintVar(&f.SegsInBuffer, "segs-in-buffer", 100, "max number of segs in perf event buffer, increate this number if message is dropped")

	flags.StringVar(&f.Format, "format", "hex", "output format (string, hex, hexstring, pcap)")

	flags.StringVar(&f.Output, "output", "", "output file, default stdout")

	flags.StringVar(&f.Sock, "sock", "", `unix socket path.
Matches all sockets starting with the given path.
Note that the path must be the same string used in the application, instead of the actual file path.
If the application used a relative path, the same relative path should be used here.
If the application runs inside a container, the path inside the container should be used here.`)

	flags.Parse()

	if f.SegSize == 0 {
		f.SegSize = 1024 * 50
	}

	if f.SegsPerMsg == 0 {
		f.SegsPerMsg = 10
	}

	if f.SegsInBuffer == 0 {
		f.SegsInBuffer = 100
	}

	return &f
}

func (f *Flags) Config() Config {
	cfg := Config{
		Pid:        uint32(f.Pid),
		SegSize:    uint32(f.SegSize),
		SegsPerMsg: uint32(f.SegsPerMsg),
	}
	copy(cfg.SockPath[:], f.Sock)
	return cfg
}
