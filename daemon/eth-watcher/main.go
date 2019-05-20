// modified version of katzenpost daemon

//nolint: dupl
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"0xacab.org/jstuczyn/CoconutGo/ethereum/watcher"
	"0xacab.org/jstuczyn/CoconutGo/ethereum/watcher/config"
)

func main() {
	cfgFile := flag.String("f", "config.toml", "Path to the watcher config file.")
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

	// Start up the watcher.
	watcher, err := watcher.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to spawn watcher instance: %v\n", err)
		os.Exit(-1)
	}

	defer watcher.Shutdown()

	// Halt the watcher gracefully on SIGINT/SIGTERM.
	go func() {
		<-haltCh
		watcher.Shutdown()
	}()

	// Wait for the server to explode or be terminated.
	watcher.Wait()
}