package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"
	coconut "0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"

	"0xacab.org/jstuczyn/CoconutGo/client"
	"0xacab.org/jstuczyn/CoconutGo/client/config"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

const providerAddress = "127.0.0.1:4000"
const providerAddress_grpc = "127.0.0.1:5000"

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

	go func() {
		for {
			<-haltCh
			fmt.Println("Received SIGTERM...")
			os.Exit(0)
		}
	}()

	params, _ := coconut.Setup(5)
	G := params.G
	pubM := getRandomAttributes(G, 3)
	privM := getRandomAttributes(G, 2)

	sig := c.SignAttributes(pubM)
	sig_grpc := c.SignAttributes_grpc(pubM)
	sigBlind := c.BlindSignAttributes(pubM, privM)
	sigBlind_grpc := c.BlindSignAttributes_grpc(pubM, privM)

	vk := c.GetAggregateVerificationKey()
	vk_grpc := c.GetAggregateVerificationKey_grpc()

	isValid := c.SendCredentialsForVerification(pubM, sig, providerAddress)
	isValid_grpc := c.SendCredentialsForVerification_grpc(pubM, sig_grpc, providerAddress_grpc)

	isValidBlind1 := c.SendCredentialsForBlindVerification(pubM, privM, sigBlind, providerAddress, nil)
	isValidBlind2 := c.SendCredentialsForBlindVerification(pubM, privM, sigBlind, providerAddress, vk)
	isValidBlind3 := c.SendCredentialsForVerification(append(privM, pubM...), sigBlind, providerAddress)
	isValidBlind1_grpc := c.SendCredentialsForBlindVerification_grpc(pubM, privM, sigBlind_grpc, providerAddress_grpc, nil)
	isValidBlind2_grpc := c.SendCredentialsForBlindVerification_grpc(pubM, privM, sigBlind_grpc, providerAddress_grpc, vk_grpc)
	isValidBlind3_grpc := c.SendCredentialsForVerification_grpc(append(privM, pubM...), sigBlind_grpc, providerAddress_grpc)

	fmt.Println("Is valid ", isValid)
	fmt.Println("Is valid local: ", coconut.Verify(params, vk, pubM, sig))

	fmt.Println("Is valid_grpc: ", isValid_grpc)
	fmt.Println("Is valid local_grpc:", coconut.Verify(params, vk_grpc, pubM, sig_grpc))

	fmt.Println("Is validBlind1:", isValidBlind1)
	fmt.Println("Is validBlind2:", isValidBlind2)
	fmt.Println("Is validBlind3:", isValidBlind3)

	fmt.Println("Is validBlind1_grpc:", isValidBlind1_grpc)
	fmt.Println("Is validBlind2_grpc:", isValidBlind2_grpc)
	fmt.Println("Is validBlind3_grpc:", isValidBlind3_grpc)
}
