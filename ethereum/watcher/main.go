package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	token "./token" // for demo
)

// Config holds configuration values
type Config struct {
	client           *ethclient.Client
	ethHost          string
	numConfirmations *big.Int       // How many blocks should we wait before we consider Ethereum to be final?
	nymContract      common.Address // Nym's ERC20 token contract
	pipeAccount      common.Address // Ethereum account that pipes Nym ERC20 into Nym Tendermint coins
}

// NewConfig returns a new Config struct
func NewConfig(ethHost string, numConfirmations int, nymContract common.Address, pipeAccount common.Address) Config {
	c := connect(ethHost)
	return Config{
		client:           c,
		numConfirmations: big.NewInt(int64(numConfirmations)),
		nymContract:      nymContract,
		pipeAccount:      pipeAccount,
	}
}

func main() {
	var ethHost = "https://ropsten.infura.io/v3/131453a5470641cd9f64942eecd8add2" // Infura used for the moment. In production should be a fullnode.
	numConfirmations := 2
	pipeAccount := common.HexToAddress("0xd6A548f60FB6F98fB29e6226DE1405c20DbbCF52")
	nymContract := common.HexToAddress("0xE80025228D5448A55B995c829B89567ECE5203d3")

	config := NewConfig(ethHost, numConfirmations, nymContract, pipeAccount)

	fmt.Println()
	fmt.Printf("Watching Ethereum blockchain at: %s \n", ethHost)
	fmt.Println()

	heartbeat := time.NewTicker(2 * time.Second)

	// Block on the heartbeat ticker
	for {
		select {
		case <-heartbeat.C:
			latestBlockNumber := getLatestBlockNumber(config)
			// latestBlockNumber := big.NewInt(int64(5422702)) // TEMP
			block := getFinalizedBlock(config, latestBlockNumber)
			for _, tx := range block.Transactions() {
				if tx.To() != nil {
					if tx.To().Hex() == config.nymContract.Hex() { // transaction used the Nym ERC20 contract
						tr := getTransactionReceipt(config, tx.Hash())
						from, to := erc20decode(*tr.Logs[0])
						if to.Hex() == config.pipeAccount.Hex() { // transaction went to the pipeAccount
							value := getValue(*tr.Logs[0])
							fmt.Printf("\n%d Nyms from %s to holding account at %s\n", value, from.Hex(), to.Hex())
						}
						fmt.Println()
					}
				}
			}
			fmt.Printf("%d ", block.Number())
		}
	}
}

// TODO: we should be able to simply return the transferEvent, instead of decoding
// from and to separately. But for some reason transferEvent.From and transferEvent.To
// are not deserializing from TokenABI in the same way as transferEvent.Tokens.
//
// Once that works we can get rid of the separate erc20Decode function.
func getValue(logData types.Log) *big.Int {
	tokenAbi, err := abi.JSON(strings.NewReader(string(token.TokenABI)))
	if err != nil {
		log.Fatal(err)
	}

	var transferEvent struct {
		From   common.Address
		To     common.Address
		Tokens *big.Int
	}

	err = tokenAbi.Unpack(&transferEvent, "Transfer", logData.Data)
	if err != nil {
		log.Fatalf("Failed to unpack transfer data: %s", err)
	}

	// Uncomment to see what I mean about From and To not deserializing:
	// fmt.Printf("Decoded To as: %s\n", transferEvent.To.Hex())
	// fmt.Printf("Decoded From as: %s\n", transferEvent.From.Hex())
	// fmt.Printf("Decoded Tokens as: %s\n", transferEvent.Tokens)
	// "Tokens" works, To and From unexpectedly come out as zeros.

	// Let's use whole tokens for display purposes. Later we'll need to figure out
	// denominations to keep things anonymized.
	var tokens = transferEvent.Tokens.Div(transferEvent.Tokens, big.NewInt(1000000000000000000))

	return tokens
}

// see https://stackoverflow.com/questions/52222758/erc20-tokens-transferred-information-from-transaction-hash re ERC20 token transfer structure
//
func erc20decode(log types.Log) (common.Address, common.Address) {
	erc20FromHash := log.Topics[1]
	erc20ToHash := log.Topics[2]
	from := common.BytesToAddress(erc20FromHash.Bytes())
	to := common.BytesToAddress(erc20ToHash.Bytes())
	return from, to
}

func getTransactionReceipt(config Config, txHash common.Hash) types.Receipt {
	tr, err := config.client.TransactionReceipt(context.Background(), txHash)
	if err != nil {
		log.Fatalf("Error getting TransactionReceipt: %s", err)
	}
	return *tr
}

func getFinalizedBlock(config Config, latestBlockNumber *big.Int) *types.Block {
	finalizedBlockNumber := latestBlockNumber.Sub(latestBlockNumber, config.numConfirmations)
	block, err := config.client.BlockByNumber(context.Background(), finalizedBlockNumber)
	if err != nil {
		log.Fatalf("Failed getting block: %s", err)
	}

	return block
}

// getFinalizedBalance returns the balance of the given account (typically the holding account)
// as it was 13 blocks ago.
//
// We use 13 blocks to approximate "finality" but PoW chains are not really "final" in any rigorous sense.
// TODO: make this configurable and recommend a number for node runners to roll the dice on in the docs.
//
// TODO: for some reason I can't find the discussion of forks which made me think that
// 13 confirmations should have a one-in-a-million chance of a fork. Dig this out as
// a reference.
//
// TODO: put the number of confirmation blocks on a config object instead of
// using magic numbers, then pass that config object in, alongside the client.
func getFinalizedBalance(config Config, addr common.Address, latestBlockNumber *big.Int) *big.Int {
	finalizedBlockNumber := latestBlockNumber.Sub(latestBlockNumber, config.numConfirmations)

	balance, err := config.client.BalanceAt(context.Background(), addr, finalizedBlockNumber)
	if err != nil {
		log.Fatalf("Error getting account balance: %s", err)
	}

	return balance
}

func getLatestBlockNumber(config Config) *big.Int {
	latestHeader, err := config.client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		log.Fatalf("Error getting latest block header: %s", err)
	}

	return latestHeader.Number
}

func connect(ethHost string) *ethclient.Client {
	client, err := ethclient.Dial(ethHost)
	if err != nil {
		log.Fatalf("Error connecting to Infura: %s", err)
	}

	return client
}

func subscribeBlocks(config Config, headers chan *types.Header) ethereum.Subscription {
	subscription, err := config.client.SubscribeNewHead(context.Background(), headers)
	if err != nil {
		log.Fatalf("Error subscribing to Ethereum blockchain: %s", err)
	}
	return subscription
}

// not in use at the moment, I've ditched subscriptions in favour of polling for now
func subscribeEventLogs(config Config, startBlock *big.Int) (chan types.Log, ethereum.Subscription) {
	query := ethereum.FilterQuery{
		Addresses: []common.Address{config.pipeAccount},
	}
	logs := make(chan types.Log)
	sub, err := config.client.SubscribeFilterLogs(context.Background(), query, logs)
	if err != nil {
		log.Fatalf("Failed subscribing to event logs: %s", err)
	}
	return logs, sub
}
