package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"0xacab.org/jstuczyn/CoconutGo/ethereum/client"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	// signature test (unrelated)
	pk, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	fmt.Println(pk)
	// if err := crypto.SaveECDSA("foo.tmp", pk); err != nil {
	// 	panic(err)
	// }

	msg := []byte("foo")
	hash := crypto.Keccak256(msg)

	sig, err := crypto.Sign(hash, pk)
	// crypto.VerifySignature()
	if err != nil {
		panic(err)
	}

	addr := crypto.PubkeyToAddress(*pk.Public().(*ecdsa.PublicKey))

	pub, err := crypto.SigToPub(hash, sig)
	if err != nil {
		panic(err)
	}

	recAddr := crypto.PubkeyToAddress(*pub)

	fmt.Println("OLD", addr.Hex())
	fmt.Println("NEW", recAddr.Hex())

	// TODO: move all of those to some .toml file
	privateKey, err := crypto.LoadECDSA("tmpPrivate")
	if err != nil {
		panic(err)
	}
	holdingContract := common.HexToAddress("0xd6A548f60FB6F98fB29e6226DE1405c20DbbCF52")
	nymContract := common.HexToAddress("0xE80025228D5448A55B995c829B89567ECE5203d3")

	log, err := logger.New("", "DEBUG", false)
	if err != nil {
		panic(err)
	}

	cfg := client.NewConfig(privateKey, []string{"https://ropsten.infura.io/v3/5607a6494adb4ad4be814ec20f46ec5b"}, nymContract, holdingContract, log)
	c, err := client.New(cfg)
	if err != nil {
		panic(err)
	}

	c.SendToHolding(context.TODO(), 42)
}
