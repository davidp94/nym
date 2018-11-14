package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jstuczyn/CoconutGo/crypto/bpgroup"

	"github.com/jstuczyn/CoconutGo/client"
	"github.com/jstuczyn/CoconutGo/client/config"
	"github.com/jstuczyn/CoconutGo/crypto/coconut/scheme"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

func getRandomAttributes(G *bpgroup.BpGroup, n int) []*Curve.BIG {
	attrs := make([]*Curve.BIG, n)
	for i := 0; i < n; i++ {
		attrs[i] = Curve.Randomnum(G.Order(), G.Rng())
	}
	return attrs
}

func main() {
	cfgFile := flag.String("f", "config.toml", "Path to the server config file.")
	flag.Parse()

	syscall.Umask(0077)

	cfg, err := config.LoadFile(*cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file '%v': %v\n", *cfgFile, err)
		os.Exit(-1)
	}

	haltCh := make(chan os.Signal)
	signal.Notify(haltCh, os.Interrupt, syscall.SIGTERM)

	// Start up the client.
	c, err := client.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to spawn client instance: %v\n", err)
		os.Exit(-1)
	}

	params, _ := coconut.Setup(5)
	G := params.G
	pubM := getRandomAttributes(G, 3)

	sig := c.SignAttributes(pubM)
	vk := c.GetAggregateVerificationKey()
	fmt.Println("Is sig valid:", coconut.Verify(params, vk, pubM, sig))

	<-haltCh

	fmt.Println("Received SIGTERM...")
}
