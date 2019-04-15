// monitor.go - Blockchain monitor.
// Copyright (C) 2019  Jedrzej Stuczynski.
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

// Package monitor implements the support for monitoring the state of the Tendermint Blockchain
// (later Ethereum I guess?) to sign all comitted requests.
package monitor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"0xacab.org/jstuczyn/CoconutGo/logger"
	"0xacab.org/jstuczyn/CoconutGo/server/storage"
	tmclient "0xacab.org/jstuczyn/CoconutGo/tendermint/client"
	"0xacab.org/jstuczyn/CoconutGo/worker"
	cmn "github.com/tendermint/tendermint/libs/common"
	ctypes "github.com/tendermint/tendermint/rpc/core/types"
	"github.com/tendermint/tendermint/types"
	"gopkg.in/op/go-logging.v1"
)

const (
	maxInterval = time.Second * 30
	// todo: figure out if we want query per tx or per block

	// txs for actual data, block header to know how many should have arrived
	// (needed if node died after sending only part of them)
	headersQuery = "tm.event = 'NewBlockHeader'"
	txsQuery     = "tm.event = 'Tx'"
)

// Monitor represents the Blockchain monitor
type Monitor struct {
	sync.Mutex
	worker.Worker
	store                      *storage.Database
	tmClient                   *tmclient.Client
	subscriberStr              string
	txsEventsCh                <-chan ctypes.ResultEvent
	headersEventsCh            <-chan ctypes.ResultEvent
	haltCh                     chan struct{}
	latestConsecutiveProcessed int64              // everything up to that point (including it) is already stored on disk
	processedBlocks            map[int64]struct{} // think of it as a set rather than a hashmap
	unprocessedBlocks          map[int64]*block

	log *logging.Logger
}

type block struct {
	sync.Mutex
	creationTime   time.Time // approximate creation time of the given struct, NOT the actual block on the chain
	height         int64
	NumTxs         int64
	receivedHeader bool
	beingProcessed bool

	Txs []*tx
}

func (b *block) isFull() bool {
	b.Lock()
	defer b.Unlock()

	if int64(len(b.Txs)) != b.NumTxs {
		return false
	}

	for i := range b.Txs {
		if b.Txs[i] == nil {
			return false
		}
	}
	return true
}

func (b *block) addTx(newTx *tx) {
	b.Lock()
	defer b.Unlock()

	if len(b.Txs) < int(newTx.index)+1 {
		newTxs := make([]*tx, newTx.index+1)
		for _, oldTx := range b.Txs {
			if oldTx != nil {
				newTxs[oldTx.index] = oldTx
			}
		}
		b.Txs = newTxs
	}
	b.Txs[newTx.index] = newTx
}

func startNewBlock(header types.Header) *block {
	return &block{
		creationTime:   time.Now(),
		height:         header.Height,
		NumTxs:         header.NumTxs,
		receivedHeader: true,
		Txs:            make([]*tx, int(header.NumTxs)),
	}
}

type tx struct {
	height int64
	index  uint32
	Code   uint32
	Tags   []cmn.KVPair
	isNil  bool
}

func startNewTx(txData types.EventDataTx) *tx {
	return &tx{
		height: txData.Height,
		index:  txData.Index,
		Code:   txData.Result.Code,
		Tags:   txData.Result.Tags,
	}
}

// FinalizeHeight gets called when all txs from a particular block are processed.
func (m *Monitor) FinalizeHeight(height int64) {
	m.log.Debugf("Finalizing height %v", height)
	m.log.Debugf("Unprocessed: \n%v\n\n\nProcessed: \n%v", m.unprocessedBlocks, m.processedBlocks)
	m.Lock()
	defer m.Unlock()
	if height == m.latestConsecutiveProcessed+1 {
		m.latestConsecutiveProcessed = height
		for i := height + 1; ; i++ {
			if _, ok := m.processedBlocks[i]; ok {
				m.log.Debugf("Also finalizing %v", i)
				m.latestConsecutiveProcessed = i
				delete(m.processedBlocks, i)
			} else {
				m.log.Debugf("%v is not in processed blocks", i)
				break
			}
		}
		m.store.FinalizeHeight(m.latestConsecutiveProcessed)
	} else {
		m.processedBlocks[height] = struct{}{}
	}
	delete(m.unprocessedBlocks, height)
}

// GetLowestFullUnprocessedBlock returns block on lowest height that is currently not being processed.
// FIXME: it doesn't actually return the lowest, but does it matter?
func (m *Monitor) GetLowestFullUnprocessedBlock() (int64, *block) {
	m.Lock()
	defer m.Unlock()
	for k, v := range m.unprocessedBlocks {
		if v.isFull() && !v.beingProcessed { // allows for multiple processors
			return k, v
		}
		m.log.Errorf("Nope %v", k)
	}
	return -1, nil
}

func (m *Monitor) addNewBlock(b *block) {
	m.Lock()
	defer m.Unlock()
	if _, ok := m.unprocessedBlocks[b.height]; !ok {
		m.unprocessedBlocks[b.height] = b
		return
	}

	m.log.Infof("Block at height: %v already present", b.height)
	if m.unprocessedBlocks[b.height].receivedHeader {
		// that's really an undefined behaviour. we probably received the same header twice?
		// ignore for now
	} else {
		oldTxs := m.unprocessedBlocks[b.height].Txs
		for _, oldTx := range oldTxs {
			if oldTx != nil {
				b.Txs[oldTx.index] = oldTx
			}
		}
		m.unprocessedBlocks[b.height] = b
	}
}

func (m *Monitor) addNewTx(newTx *tx) {
	m.Lock()
	defer m.Unlock()
	b, ok := m.unprocessedBlocks[newTx.height]
	if !ok {
		// we haven't received block header  and this is the first tx we received for that block
		tempBlock := &block{
			creationTime:   time.Now(),
			height:         newTx.height,
			NumTxs:         -1,
			receivedHeader: false,
			Txs:            make([]*tx, int(newTx.index)+1), // we know that there are at least that many txs in the block
		}
		tempBlock.Txs[newTx.index] = newTx
		m.unprocessedBlocks[newTx.height] = tempBlock
		return
	}
	b.addTx(newTx)
}

func (m *Monitor) addNewCatchUpBlock(res *ctypes.ResultBlockResults, overwrite bool) {
	m.Lock()
	defer m.Unlock()

	m.log.Infof("Catching up on block %v", res.Height)

	// ensure it's not in blocks to be processed or that are processed
	// TODO: overwrite, etc.
	if _, ok := m.unprocessedBlocks[res.Height]; !ok && res.Height > m.latestConsecutiveProcessed {
		if _, ok := m.processedBlocks[res.Height]; !ok {

			b := &block{
				creationTime:   time.Now(),
				height:         res.Height,
				NumTxs:         int64(len(res.Results.DeliverTx)),
				receivedHeader: true,
				Txs:            make([]*tx, len(res.Results.DeliverTx)),
			}

			for i, resTx := range res.Results.DeliverTx {
				if resTx == nil {
					b.Txs[i] = &tx{
						isNil: true,
					}
					continue
				}
				b.Txs[i] = &tx{
					height: res.Height,
					index:  uint32(i),
					Code:   resTx.Code,
					Tags:   resTx.Tags,
				}
			}
			m.unprocessedBlocks[res.Height] = b
		}
	}
}

// gets blockchain data from startHeight to endHeight (both inclusive)
func (m *Monitor) catchUp(startHeight, endHeight int64) {
	m.log.Infof("Catching up from %v to %v", startHeight, endHeight)
	// according to docs, blockchaininfo can return at most 20 items
	if endHeight-startHeight >= 20 {
		m.log.Debug("There are more than 20 blocks to catchup on")
		m.catchUp(startHeight, startHeight+19)
		m.catchUp(startHeight+20, endHeight)
	}

	res, err := m.tmClient.BlockchainInfo(startHeight, endHeight)
	if err != nil {
		// TODO:
		// how should we behave on error, panic, return, etc?
		m.log.Critical("Error on catchup")
	}

	for _, blockMeta := range res.BlockMetas {
		header := blockMeta.Header
		if header.NumTxs == 0 {
			// then we can just add the block and forget about it
			m.addNewBlock(startNewBlock(header))
		} else {
			// otherwise we need to get tx details
			// TODO: parallelize it perhaps?
			blockRes, err := m.tmClient.BlockResults(&header.Height)
			if err != nil {
				// TODO:
				// same issue, how to behave?; panic, return, etc?
				m.log.Critical("Error on catchup")
			}
			m.addNewCatchUpBlock(blockRes, false)
		}
	}
}

func (m *Monitor) resyncWithBlockchain() error {
	latestStored := m.store.GetHighest()
	m.log.Debug("Resyncing blocks with the chain")
	latestBlock, err := m.tmClient.BlockResults(nil)
	if err != nil {
		return err
	}

	if latestBlock.Height != latestStored {
		m.log.Warningf("Monitor is behind the blockchain. Latest stored height: %v, latest block height: %v", latestStored, latestBlock.Height)
		m.addNewCatchUpBlock(latestBlock, false)
		m.catchUp(latestStored+1, latestBlock.Height-1)
	} else {
		m.log.Notice("Monitor is up to date with the blockchain")
	}
	return nil
}

func (m *Monitor) resubscribeToBlockchain() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	headersEventsCh, err := m.tmClient.Subscribe(ctx, m.subscriberStr, headersQuery)
	if err != nil {
		return err
	}
	m.log.Debug("Resubscribed to new headers")

	txsEventsCh, err := m.tmClient.Subscribe(ctx, m.subscriberStr, txsQuery)
	if err != nil {
		return err
	}
	m.log.Debug("Resubscribed to new txs")

	m.headersEventsCh = headersEventsCh
	m.txsEventsCh = txsEventsCh

	return nil
}

func (m *Monitor) resubscribeToBlockchainFull() error {
	m.log.Notice("Resubscribing to the blockchain")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	if err := m.tmClient.UnsubscribeAll(ctx, m.subscriberStr); err != nil {
		m.log.Noticef("%v", err)
	}

	if err := m.resubscribeToBlockchain(); err != nil {
		err := m.tmClient.ForceReconnect()
		if err != nil {
			return err
		}
		// after reconnecting to new node we try to recreate the subscriptions again
		return m.resubscribeToBlockchain()
	}
	return nil
}

// for now assume we receive all subscription events and nodes never go down
func (m *Monitor) worker() {
	timeoutTicker := time.NewTicker(maxInterval)
	for {
		select {
		case e := <-m.headersEventsCh:
			headerData := e.Data.(types.EventDataNewBlockHeader).Header

			m.log.Noticef("Received header for height : %v", headerData.Height)
			m.addNewBlock(startNewBlock(headerData))
			// reset ticker on each successful read
			timeoutTicker = time.NewTicker(maxInterval)

		case e := <-m.txsEventsCh:
			txData := e.Data.(types.EventDataTx)

			m.log.Noticef("Received tx %v height: %v", txData.Index, txData.Height)
			m.addNewTx(startNewTx(txData))
			// reset ticker on each successful read
			timeoutTicker = time.NewTicker(maxInterval)

		case <-timeoutTicker.C:
			// on target environment we assume regular-ish block intervals with empty blocks if needed.
			// if we dont hear anything back, we assume a failure.
			m.log.Warningf("Timeout - Didn't receive any data in %v seconds", maxInterval)
			m.log.Debugf("%v blocks to be processed", len(m.unprocessedBlocks))

			if err := m.resubscribeToBlockchainFull(); err != nil {
				// what to do now?
				m.log.Critical(fmt.Sprintf("Couldn't resubscribe to the blockchain: %v", err))
				return
			}
			if err := m.resyncWithBlockchain(); err != nil {
				// again, what to do now? But at least we're connected so we could theoretically receive some data?
				m.log.Errorf("Couldn't resync with the blockchain: %v", err)
			}

			// for now do a dummy catchup as in on everything after last stored block.
			// later improve and do it selectively

		case <-m.haltCh:
			return
		}
	}
}

// Halt stops the monitor and unsubscribes from any open queries.
func (m *Monitor) Halt() {
	m.log.Debugf("Halting the monitor")
	close(m.haltCh)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	if err := m.tmClient.UnsubscribeAll(ctx, m.subscriberStr); err != nil {
		m.log.Noticef("%v", err)
	}
	m.Worker.Halt()
}

// New creates a new monitor.
func New(l *logger.Logger, tmClient *tmclient.Client, store *storage.Database, id int) (*Monitor, error) {
	// read db with current state etc
	subscriberStr := fmt.Sprintf("monitor%v", id)
	log := l.GetLogger("Monitor")

	// in case we didn't shutdown cleanly last time
	if err := tmClient.UnsubscribeAll(context.Background(), subscriberStr); err != nil {
		log.Noticef("%v", err)
	}

	monitor := &Monitor{
		tmClient:                   tmClient,
		store:                      store,
		log:                        log,
		subscriberStr:              subscriberStr,
		haltCh:                     make(chan struct{}),
		unprocessedBlocks:          make(map[int64]*block),
		processedBlocks:            make(map[int64]struct{}),
		latestConsecutiveProcessed: store.GetHighest(),
	}

	if err := monitor.resubscribeToBlockchain(); err != nil {
		return nil, err
	}

	if err := monitor.resyncWithBlockchain(); err != nil {
		return nil, err
	}

	monitor.Go(monitor.worker)
	return monitor, nil
}
