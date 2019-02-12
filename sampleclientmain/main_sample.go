// main_sample.go - sample usage for coconut/tendermint client
// Copyright (C) 2018-2019  Jedrzej Stuczynski.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"0xacab.org/jstuczyn/CoconutGo/tendermint/account"

	"0xacab.org/jstuczyn/CoconutGo/constants"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/nym/token"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/code"
	"0xacab.org/jstuczyn/CoconutGo/tendermint/nymabci/transaction"

	cclient "0xacab.org/jstuczyn/CoconutGo/client"
	"0xacab.org/jstuczyn/CoconutGo/client/config"
	"0xacab.org/jstuczyn/CoconutGo/crypto/bpgroup"
	"0xacab.org/jstuczyn/CoconutGo/crypto/coconut/scheme"
	tmclient "0xacab.org/jstuczyn/CoconutGo/tendermint/client"
	Curve "github.com/jstuczyn/amcl/version3/go/amcl/BLS381"
)

const providerAddress = "127.0.0.1:4000"
const providerAddressGrpc = "127.0.0.1:5000"

func getRandomAttributes(G *bpgroup.BpGroup, n int) []*Curve.BIG {
	attrs := make([]*Curve.BIG, n)
	for i := 0; i < n; i++ {
		attrs[i] = Curve.Randomnum(G.Order(), G.Rng())
	}
	return attrs
}

// nolint: gosec, lll, errcheck
func main() {

	acc := account.NewAccount()
	acc.ToJSONFile("ia3.json")

	return
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

	// Start up the coconut client.
	cc, err := cclient.New(cfg)
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
	// pubM := getRandomAttributes(G, 3)
	// privM := getRandomAttributes(G, 2)

	// generate token
	value := int32(1000)
	seq := Curve.Randomnum(params.P(), G.Rng())
	privateKey := Curve.Randomnum(params.P(), G.Rng())

	token := token.New(seq, privateKey, value)
	pubM, privM := token.GetPublicAndPrivateSlices()

	// get credential
	sig, _ := cc.BlindSignAttributes(pubM, privM)

	// get aggregate vk needed for show protocol
	avk, _ := cc.GetAggregateVerificationKey()

	// generate random merchant (abci is set to create new accounts for new merchants)
	merchantAddrEC := Curve.G1mul(params.G1(), Curve.Randomnum(params.P(), params.G.Rng()))
	merchantAddr := make([]byte, constants.ECPLen)
	merchantAddrEC.ToBytes(merchantAddr, true)

	// tendermint-abci client
	log, err := logger.New("", "DEBUG", false)
	if err != nil {
		panic(fmt.Sprintf("Failed to create a logger: %v", err))
	}

	tmclient, err := tmclient.New("tcp://0.0.0.0:46667", log)
	if err != nil {
		panic(fmt.Sprintf("Failed to create a tmclient: %v", err))
	}

	reqT, err := transaction.CreateNewDepositCoconutCredentialRequest(params, avk, sig, token, merchantAddr)
	if err != nil {
		panic(err)
	}

	res, _ := tmclient.Broadcast(reqT)
	fmt.Printf("Deposited Credential. Code: %v, additional data: %v\n", code.ToString(res.DeliverTx.Code), res.DeliverTx.Data)

	// all possible interactions with the IAs/SPs
	//
	// if cfg.Client.UseGRPC {
	// 	sigGrpc, _ := cc.SignAttributesGrpc(pubM)
	// 	sigBlindGrpc, _ := cc.BlindSignAttributesGrpc(pubM, privM)
	// 	vkGrpc, _ := cc.GetAggregateVerificationKeyGrpc()

	// 	isValidGrpc, _ := cc.SendCredentialsForVerificationGrpc(pubM, sigGrpc, providerAddressGrpc)
	// 	isValidBlind1Grpc, _ := cc.SendCredentialsForBlindVerificationGrpc(pubM, privM, sigBlindGrpc, providerAddressGrpc, nil)
	// 	isValidBlind2Grpc, _ := cc.SendCredentialsForBlindVerificationGrpc(pubM, privM, sigBlindGrpc, providerAddressGrpc, vkGrpc)
	// 	isValidBlind3Grpc, _ := cc.SendCredentialsForVerificationGrpc(append(privM, pubM...), sigBlindGrpc, providerAddressGrpc)

	// 	fmt.Println("Is validGrpc: ", isValidGrpc)
	// 	fmt.Println("Is valid localGrpc:", coconut.Verify(params, vkGrpc, pubM, sigGrpc))

	// 	fmt.Println("Is validBlind1Grpc:", isValidBlind1Grpc)
	// 	fmt.Println("Is validBlind2Grpc:", isValidBlind2Grpc)
	// 	fmt.Println("Is validBlind3Grpc:", isValidBlind3Grpc)
	// } else {
	// 	sig, _ := cc.SignAttributes(pubM)
	// 	sigBlind, _ := cc.BlindSignAttributes(pubM, privM)
	// 	vk, _ := cc.GetAggregateVerificationKey()

	// 	isValid, _ := cc.SendCredentialsForVerification(pubM, sig, providerAddress)
	// 	isValidBlind1, _ := cc.SendCredentialsForBlindVerification(pubM, privM, sigBlind, providerAddress, nil)
	// 	isValidBlind2, _ := cc.SendCredentialsForBlindVerification(pubM, privM, sigBlind, providerAddress, vk)
	// 	isValidBlind3, _ := cc.SendCredentialsForVerification(append(privM, pubM...), sigBlind, providerAddress)

	// 	fmt.Println("Is valid ", isValid)
	// 	fmt.Println("Is valid local: ", coconut.Verify(params, vk, pubM, sig))

	// 	fmt.Println("Is validBlind1:", isValidBlind1)
	// 	fmt.Println("Is validBlind2:", isValidBlind2)
	// 	fmt.Println("Is validBlind3:", isValidBlind3)
	// }
}
