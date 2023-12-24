// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Leon Hwang.

package sockdump

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const PCAP_LINK_TYPE = 147 // DLT_USER_0

type Output struct {
	w *os.File

	pcapw *pcapgo.Writer

	outputFn func(*Packet, []byte)
}

func NewOutput(format, output string, segSize uint) (*Output, error) {
	var o Output

	if output == "" {
		o.w = os.Stdout
	} else {
		f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return nil, fmt.Errorf("failed to open output file: %w", err)
		}
		o.w = f
	}

	switch format {
	case "string":
		o.outputFn = o.outputString
	case "hex":
		o.outputFn = o.outputHex
	case "hexstring":
		o.outputFn = o.outputHexString
	case "pcap":
		o.outputFn = o.outputPcap
		o.pcapw = pcapgo.NewWriter(o.w)
		if err := o.pcapw.WriteFileHeader(uint32(segSize), layers.LinkType(PCAP_LINK_TYPE)); err != nil {
			_ = o.Close()
			return nil, fmt.Errorf("failed to write pcap header: %w", err)
		}
	default:
		return nil, fmt.Errorf("invalid format %s", format)
	}

	return &o, nil
}

func (o *Output) Close() error {
	if o.w != os.Stdout {
		return o.w.Close()
	}
	return nil
}

func (o *Output) Output(pkt *Packet) {
	o.outputFn(pkt, pkt.Data[:pkt.Len])
}

func (o *Output) printHeader(pkt *Packet, data []byte) {
	fmt.Fprintf(o.w, "%s >>> process %d/%s [%d -> %d] path %s len %d(%d)\n",
		time.Now().Format(time.DateTime), pkt.Pid,
		nullTerminatedString(pkt.Comm[:]), pkt.Pid, pkt.PeerPid,
		nullTerminatedString(pkt.Path[:]), len(data), pkt.Len)
}

func (o *Output) outputString(pkt *Packet, data []byte) {
	o.printHeader(pkt, data)
	if len(data) == 0 {
		return
	}

	if pkt.Flags != 0 {
		fmt.Fprintln(o.w, "error")
	} else {
		fmt.Fprintf(o.w, "%s\n", nullTerminatedString(data))
	}
}

func (o *Output) outputHex(pkt *Packet, data []byte) {
	o.printHeader(pkt, data)
	if len(data) == 0 {
		return
	}

	if pkt.Flags != 0 {
		fmt.Fprintln(o.w, "error")
	} else {
		fmt.Fprintln(o.w, hex.Dump(data))
	}
}

func (o *Output) outputHexString(pkt *Packet, data []byte) {
	o.printHeader(pkt, data)
	if len(data) == 0 {
		return
	}

	if pkt.Flags != 0 {
		fmt.Fprintln(o.w, "error")
	} else {
		fmt.Fprintf(o.w, "%s\n", hex.EncodeToString(data))
	}
}

func (o *Output) outputPcap(pkt *Packet, data []byte) {
	if len(data) == 0 {
		return
	}

	if pkt.Flags != 0 {
		return
	}

	var header [16]byte
	binary.BigEndian.PutUint64(header[0:8], uint64(pkt.Pid))
	binary.BigEndian.PutUint64(header[8:16], uint64(pkt.PeerPid))
	data = append(header[:], data...)

	if err := o.pcapw.WritePacket(gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		CaptureLength:  len(data),
		Length:         len(data),
		InterfaceIndex: 0,
	}, data); err != nil {
		log.Printf("failed to write pcap packet: %v", err)
	}
}

func nullTerminated(s []byte) []byte {
	for i, b := range s {
		if b == '\000' {
			return s[:i]
		}
	}
	return s
}

func nullTerminatedString(s []byte) string {
	s = nullTerminated(s)
	if len(s) == 0 {
		return ""
	}
	return unsafe.String(&s[0], len(s))
}
