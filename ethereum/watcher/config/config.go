package config

import (
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// TODO: toml file similar to client and server. This is just a temporary solution to make everything run

// Config holds configuration values
type Config struct {
	Client           *ethclient.Client
	ethHost          string
	NumConfirmations *big.Int       // How many blocks should we wait before we consider Ethereum to be final?
	NymContract      common.Address // Nym's ERC20 token contract
	PipeAccount      common.Address // Ethereum account that pipes Nym ERC20 into Nym Tendermint coins
}

// will definitely be moved to the watcher file
func connect(ethHost string) *ethclient.Client {
	client, err := ethclient.Dial(ethHost)
	if err != nil {
		log.Fatalf("Error connecting to Infura: %s", err)
	}

	return client
}

// NewConfig returns a new Config struct
func NewConfig(ethHost string, numConfirmations int, nymContract common.Address, pipeAccount common.Address) Config {
	c := connect(ethHost)
	return Config{
		Client:           c,
		NumConfirmations: big.NewInt(int64(numConfirmations)),
		NymContract:      nymContract,
		PipeAccount:      pipeAccount,
	}
}
