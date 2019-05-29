// modified version of katzenpost daemon

//nolint: dupl
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"

	"0xacab.org/jstuczyn/CoconutGo/server"
	"0xacab.org/jstuczyn/CoconutGo/server/config"
)

func main() {
	const PtrSize = 32 << uintptr(^uintptr(0)>>63)
	if PtrSize != 64 || strconv.IntSize != 64 {
		fmt.Fprintf(os.Stderr,
			"The binary seems to not have been compiled in 64bit mode. Runtime pointer size: %v, Int size: %v\n",
			PtrSize,
			strconv.IntSize,
		)
		os.Exit(-1)
	}

	cfgFile := flag.String("f", "config.toml", "Path to the server config file.")
	flag.Parse()

	syscall.Umask(0077)

	// Ensure that a sane number of OS threads is allowed.
	if os.Getenv("GOMAXPROCS") == "" {
		// But only if the user isn't trying to override it.
		nProcs := runtime.GOMAXPROCS(0)
		nCPU := runtime.NumCPU()
		if nProcs < nCPU {
			runtime.GOMAXPROCS(nCPU)
		}
	}

	cfg, err := config.LoadFile(*cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file '%v': %v\n", *cfgFile, err)
		os.Exit(-1)
	}

	// Setup the signal handling.
	haltCh := make(chan os.Signal)
	signal.Notify(haltCh, os.Interrupt, syscall.SIGTERM)
	// for now ignore SIGHUP signal, todo: handle it similarly to katzenpost

	// Start up the server.
	svr, err := server.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to spawn server instance: %v\n", err)
		os.Exit(-1)
	}
	defer svr.Shutdown()

	// Halt the server gracefully on SIGINT/SIGTERM.
	go func() {
		<-haltCh
		svr.Shutdown()
	}()

	// Wait for the server to explode or be terminated.
	svr.Wait()
}
