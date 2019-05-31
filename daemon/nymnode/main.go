package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"

	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymnode"
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

	cfgFilePtr := flag.String("cfgFile", "/tendermint/config/config.toml", "The main tendermint configuration file")
	dataRootPtr := flag.String("dataRoot", "/tendermint", "The data root directory")
	createEmptyBlocksPtr := flag.Bool("createEmptyBlocks",
		false,
		"Flag to indicate whether tendermint should create empty blocks",
	)
	emptyBlocksIntervalPtr := flag.Duration("emptyBlocksInterval",
		0,
		"(if applicable) used to indicate interval between empty blocks",
	)
	flag.Parse()

	node, err := nymnode.CreateNymNode(*cfgFilePtr, *dataRootPtr, *createEmptyBlocksPtr, *emptyBlocksIntervalPtr)
	if err != nil {
		panic(err)
	}

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

	if err = node.Start(); err != nil {
		fmt.Printf("Failed to start node: %+v\n", err)
		panic(err)
	}

	// Trap signal, run forever.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	<-c
	if err := node.Stop(); err != nil {
		fmt.Println(err)
	}
	fmt.Println("Node was stopped")
}
