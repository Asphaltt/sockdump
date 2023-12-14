// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Leon Hwang.

package sockdump

type Packet struct {
	Pid     uint32
	PeerPid uint32
	Len     uint32
	Flags   uint32
	Comm    [16]byte
	Path    [108]byte
	Data    [1024 * 50]byte
}

type Config struct {
	Pid        uint32
	SegSize    uint32
	SegsPerMsg uint32
	SockPath   [108]byte
}
