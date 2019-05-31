package main

import (
	"context"

	"0xacab.org/jstuczyn/CoconutGo/ethereum/client"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// just sends some tokens to the pipe account
func main() {
	// TODO: move all of those to some .toml file
	privateKey, err := crypto.LoadECDSA("tmpPrivate")
	if err != nil {
		panic(err)
	}
	pipeContract := common.HexToAddress("0xd6A548f60FB6F98fB29e6226DE1405c20DbbCF52")
	nymContract := common.HexToAddress("0xE80025228D5448A55B995c829B89567ECE5203d3")

	log, err := logger.New("", "DEBUG", false)
	if err != nil {
		panic(err)
	}

	cfg := client.NewConfig(privateKey,
		[]string{"https://ropsten.infura.io/v3/5607a6494adb4ad4be814ec20f46ec5b"}, nymContract, pipeContract, log)
	c, err := client.New(cfg)
	if err != nil {
		panic(err)
	}

	if err := c.TransferERC20Tokens(context.TODO(), 1, nymContract, pipeContract); err != nil {
		panic(err)
	}
}
