// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Leon Hwang.

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/Asphaltt/sockdump/internal/sockdump"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang sockdump ./bpf/sockdump.c -- -D__TARGET_ARCH_x86 -I./bpf/headers -Wall -O2

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock rlimit: %v", err)
	}

	flags := sockdump.NewFlags()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec, err := loadSockdump()
	if err != nil {
		log.Fatalf("Failed to load sockdump: %v", err)
	}

	if err := spec.RewriteConstants(map[string]interface{}{
		"CONFIG": flags.Config(),
	}); err != nil {
		log.Fatalf("Failed to rewrite constants: %v", err)
	}

	haveFentry := sockdump.HaveBPFLinkTracing()
	if haveFentry {
		delete(spec.Programs, "kprobe__unix_stream_sendmsg")
		delete(spec.Programs, "kprobe__unix_dgram_sendmsg")
	} else {
		delete(spec.Programs, "fentry__unix_stream_sendmsg")
		delete(spec.Programs, "fentry__unix_dgram_sendmsg")
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize:     ebpf.DefaultVerifierLogSize * 10,
			LogDisabled: false,
		},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load collection: %v\n%+v", err, ve)
		} else {
			log.Fatalf("Failed to load collection: %v", err)
		}
	}
	defer coll.Close()

	if haveFentry {
		if l, err := link.AttachTracing(link.TracingOptions{
			Program: coll.Programs["fentry__unix_stream_sendmsg"],
		}); err != nil {
			log.Fatalf("Failed to attach fentry: %v", err)
		} else {
			log.Println("Attached fentry to unix_stream_sendmsg")
			defer l.Close()
		}

		if l, err := link.AttachTracing(link.TracingOptions{
			Program: coll.Programs["fentry__unix_dgram_sendmsg"],
		}); err != nil {
			log.Fatalf("Failed to attach fentry: %v", err)
		} else {
			log.Println("Attached fentry to unix_dgram_sendmsg")
			defer l.Close()
		}
	} else {
		if kp, err := link.Kprobe("unix_stream_sendmsg", coll.Programs["kprobe__unix_stream_sendmsg"], nil); err != nil {
			log.Fatalf("Failed to attach kprobe %s: %v", "unix_stream_sendmsg", err)
		} else {
			log.Println("Attached kprobe to unix_stream_sendmsg")
			defer kp.Close()
		}

		if kp, err := link.Kprobe("unix_dgram_sendmsg", coll.Programs["kprobe__unix_dgram_sendmsg"], nil); err != nil {
			log.Fatalf("Failed to attach kprobe %s: %v", "unix_dgram_sendmsg", err)
		} else {
			log.Println("Attached kprobe to unix_dgram_sendmsg")
			defer kp.Close()
		}
	}

	bufferSize := int(unsafe.Sizeof(sockdump.Packet{})) * int(flags.SegsInBuffer)
	reader, err := perf.NewReader(coll.Maps["events"], bufferSize)
	if err != nil {
		log.Fatalf("Failed to create perf reader: %v", err)
	}
	defer reader.Close()

	output, err := sockdump.NewOutput(flags.Format, flags.Output, flags.SegSize)
	if err != nil {
		log.Fatalf("Failed to create output: %v", err)
	}
	defer output.Close()

	var pktCnt int
	go func() {
		<-ctx.Done()
		_ = reader.Close()
		fmt.Fprintln(os.Stderr)
		log.Printf("Captured %d packets", pktCnt)
	}()

	log.Println("Read data from perf event...")

	var pkt sockdump.Packet
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Fatalf("Failed to read record: %v", err)
		}

		if record.LostSamples != 0 {
			log.Printf("Lost %d packets in perf event", record.LostSamples)
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &pkt); err != nil {
			log.Printf("Failed to parse perf event: %v", err)
			continue
		}

		output.Output(&pkt)

		pktCnt++
	}
}
