package watcher

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/ethereum/watcher/config"
	token "0xacab.org/jstuczyn/CoconutGo/ethereum/watcher/token"
	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/worker"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"gopkg.in/op/go-logging.v1"
)

type Watcher struct {
	cfg *config.Config
	worker.Worker

	log *logging.Logger

	haltedCh chan struct{}
	haltOnce sync.Once
}

// Wait waits till the Watcher is terminated for any reason.
func (w *Watcher) Wait() {
	<-w.haltedCh
}

// Shutdown cleanly shuts down a given Watcher instance.
func (w *Watcher) Shutdown() {
	w.haltOnce.Do(func() { w.halt() })
}

// right now it's only using a single worker so all of this is redundant,
// but more future proof if we decided to include more workers
func (w *Watcher) halt() {
	w.log.Notice("Starting graceful shutdown.")

	w.Worker.Halt()

	w.log.Notice("Shutdown complete.")

	close(w.haltedCh)
}

// TODO: all will need to be made into methods, and split to separate packages

// stop etc are not working
func (w *Watcher) worker() {

	fmt.Println()
	fmt.Printf("Watching Ethereum blockchain at: %s \n", w.cfg.Watcher.EthereumNodeAddress)
	fmt.Println()

	// again, more temp code
	pipeAccount := common.HexToAddress(w.cfg.Watcher.PipeAccount)
	nymContract := common.HexToAddress(w.cfg.Watcher.NymContract)

	heartbeat := time.NewTicker(2 * time.Second)

	// Block on the heartbeat ticker
	for {
		select {
		case <-w.HaltCh():
			return
		case <-heartbeat.C:
			latestBlockNumber := w.getLatestBlockNumber()
			// latestBlockNumber := big.NewInt(int64(5422702)) // TEMP
			block := w.getFinalizedBlock(latestBlockNumber)
			for _, tx := range block.Transactions() {
				if tx.To() != nil {
					if tx.To().Hex() == nymContract.Hex() { // transaction used the Nym ERC20 contract
						tr := w.getTransactionReceipt(tx.Hash())
						from, to := erc20decode(*tr.Logs[0])
						if to.Hex() == pipeAccount.Hex() { // transaction went to the pipeAccount
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

func (w *Watcher) getTransactionReceipt(txHash common.Hash) types.Receipt {
	tr, err := w.cfg.Watcher.Client.TransactionReceipt(context.Background(), txHash)
	if err != nil {
		log.Fatalf("Error getting TransactionReceipt: %s", err)
	}
	return *tr
}

func (w *Watcher) getFinalizedBlock(latestBlockNumber *big.Int) *types.Block {
	finalizedBlockNumber := latestBlockNumber.Sub(latestBlockNumber, big.NewInt(w.cfg.Debug.NumConfirmations))
	block, err := w.cfg.Watcher.Client.BlockByNumber(context.Background(), finalizedBlockNumber)
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
func (w *Watcher) getFinalizedBalance(addr common.Address, latestBlockNumber *big.Int) *big.Int {
	finalizedBlockNumber := latestBlockNumber.Sub(latestBlockNumber, big.NewInt(w.cfg.Debug.NumConfirmations))

	balance, err := w.cfg.Watcher.Client.BalanceAt(context.Background(), addr, finalizedBlockNumber)
	if err != nil {
		log.Fatalf("Error getting account balance: %s", err)
	}

	return balance
}

func (w *Watcher) getLatestBlockNumber() *big.Int {
	latestHeader, err := w.cfg.Watcher.Client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		log.Fatalf("Error getting latest block header: %s", err)
	}

	return latestHeader.Number
}

func (w *Watcher) subscribeBlocks(headers chan *types.Header) ethereum.Subscription {
	subscription, err := w.cfg.Watcher.Client.SubscribeNewHead(context.Background(), headers)
	if err != nil {
		log.Fatalf("Error subscribing to Ethereum blockchain: %s", err)
	}
	return subscription
}

// not in use at the moment, I've ditched subscriptions in favour of polling for now
func (w *Watcher) subscribeEventLogs(startBlock *big.Int) (chan types.Log, ethereum.Subscription) {
	query := ethereum.FilterQuery{
		Addresses: []common.Address{common.HexToAddress(w.cfg.Watcher.PipeAccount)},
	}
	logs := make(chan types.Log)
	sub, err := w.cfg.Watcher.Client.SubscribeFilterLogs(context.Background(), query, logs)
	if err != nil {
		log.Fatalf("Failed subscribing to event logs: %s", err)
	}
	return logs, sub
}

// func New(cfg *config.Config) (*Watcher, error) {
func New(cfg *config.Config) (*Watcher, error) {
	log, err := logger.New(cfg.Logging.File, cfg.Logging.Level, cfg.Logging.Disable)
	if err != nil {
		return nil, fmt.Errorf("Failed to create a logger: %v", err)
	}
	watcherLog := log.GetLogger("Client")
	watcherLog.Noticef("Logging level set to %v", cfg.Logging.Level)

	w := &Watcher{
		cfg:      cfg,
		log:      watcherLog,
		haltedCh: make(chan struct{}),
	}

	w.Go(w.worker)

	return w, nil
}
