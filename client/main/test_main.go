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

const providerAddress = "127.0.0.1:4001"

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
	// privM := getRandomAttributes(G, 2)

	sig := c.SignAttributes(pubM)
	// sig := c.BlindSignAttributes(privM, pubM)

	// I've killed one signer and created new vk (with valid keys) during the time
	// this will be done in proper tests later
	// time.Sleep(10 * time.Second)
	vk := c.GetAggregateVerificationKey()
	isValid := c.SendCredentialsForVerification(pubM, sig, providerAddress)
	vks := c.GetVerificationKeys(false)
	if vk != nil {
		fmt.Println("Is sig valid:", isValid)
		// fmt.Println("Is sig valid:", coconut.BlindVerify(params, vk, sig, blindShowMats, pubM))
		// fmt.Println("Is sig valid:", coconut.Verify(params, vk, append(privM, pubM...), sig))
		fmt.Println("Is sig valid:2", coconut.Verify(params, vks[1], pubM, sig))

	}

	<-haltCh

	fmt.Println("Received SIGTERM...")
}
