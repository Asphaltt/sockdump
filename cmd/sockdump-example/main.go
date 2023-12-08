// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Leon Hwang.

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	"golang.org/x/sync/errgroup"
)

func main() {
	fpath := "/"
	if len(os.Args) > 1 && os.Args[1] != "" {
		fpath = os.Args[1]
	}

	sockPath := "/tmp/sockdump.sock"

	ctx, cancel := context.WithCancel(context.Background())
	errg, ctx := errgroup.WithContext(ctx)

	serving := make(chan struct{})
	errg.Go(func() error {
		return runServer(ctx, sockPath, serving)
	})

	errg.Go(func() error {
		<-serving
		err := runClient(sockPath, fpath)
		cancel()
		return err
	})

	_ = errg.Wait()
}

func runServer(ctx context.Context, sockPath string, serving chan struct{}) error {
	server := http.Server{
		Handler: http.FileServer(http.Dir("/tmp")),
	}

	unixListener, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer unixListener.Close()

	unixListener.(*net.UnixListener).SetUnlinkOnClose(true)

	close(serving)

	go func() {
		<-ctx.Done()
		server.Close()
	}()

	log.Println("serving")

	server.Serve(unixListener)

	return nil
}

func runClient(sockPath, fpath string) error {
	httpc := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		},
	}

	response, err := httpc.Get("http://unix/" + fpath)
	if err != nil {
		return fmt.Errorf("failed to get: %w", err)
	}
	defer response.Body.Close()

	log.Println("got response")

	io.Copy(os.Stdout, response.Body)

	return nil
}
